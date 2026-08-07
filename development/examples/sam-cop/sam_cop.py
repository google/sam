import asyncio
import json
import os
import re
import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Dict, List, Optional, Any, Tuple

from sam_mcp.client import SamClient

from channels import Channel, build_channels


@dataclass
class SamCopConfig:
    poll_interval: float
    miss_threshold: int
    min_peers: int


def load_config(env) -> SamCopConfig:
    return SamCopConfig(
        poll_interval=float(env.get("POLL_INTERVAL", "30")),
        miss_threshold=int(env.get("MISS_THRESHOLD", "3")),
        min_peers=int(env.get("MIN_PEERS", "1")),
    )


@dataclass
class Alert:
    severity: str
    title: str
    description: str
    peer_id: str = ""
    service: str = ""


SEVERITY_EMOJI = {"critical": "🚨", "warning": "⚠️", "info": "ℹ️"}

CONTROL_CHARS_RE = re.compile(r"[\x00-\x1f\x7f]+")


def sanitize_alert_text(text: str, limit: int = 200) -> str:
    """Strips control chars (incl. newlines) so attacker-controlled strings can't forge alert lines."""
    cleaned = CONTROL_CHARS_RE.sub(" ", text).strip()
    if len(cleaned) > limit:
        cleaned = cleaned[:limit].rstrip() + "..."
    return cleaned


def format_alert(alert: Alert, node_peer_id: str, timestamp: str) -> str:
    title = sanitize_alert_text(alert.title)
    lines = [f"{SEVERITY_EMOJI[alert.severity]} [{alert.severity.upper()}] {title}"]
    if alert.description:
        lines.append(sanitize_alert_text(alert.description))
    if alert.peer_id:
        lines.append(f"peer: {sanitize_alert_text(alert.peer_id)}")
    if alert.service:
        lines.append(f"service: {sanitize_alert_text(alert.service)}")
    lines.append(f"reported by {node_peer_id} at {timestamp}")
    return "\n".join(lines)


async def deliver(channels: List[Channel], message: str) -> None:
    async def deliver_to_channel(channel: Channel) -> None:
        for attempt in range(3):
            try:
                await channel.send(message)
                return
            except Exception as error:
                if attempt == 2:
                    print(f"[-] {channel.name} delivery failed after 3 attempts: {error}", flush=True)
                else:
                    await asyncio.sleep(2**attempt)

    # Concurrent so one slow or failing channel's retries don't delay the others.
    await asyncio.gather(*(deliver_to_channel(channel) for channel in channels))


SEVERITY_BY_EVENT_TYPE = {
    "banned": "critical",
    "spoofing_attempt": "critical",
    "stale_event": "warning",
    "rate_limit_drop": "warning",
    "key_rotation": "warning",
    "policy_update": "info",
}

# Event types that arrive as attacker-controlled floods and get aggregated per peer per cycle.
AGGREGATED_EVENT_TYPES = ("rate_limit_drop", "spoofing_attempt", "stale_event")


@dataclass
class SamCopState:
    cursor: int = 0
    baseline: set = field(default_factory=set)
    miss_counts: dict = field(default_factory=dict)
    partitioned: bool = False
    first_snapshot: bool = True


def detect_partition(state: SamCopState, connected_peer_count: int, min_peers: int) -> List[Alert]:
    alerts = []
    if connected_peer_count < min_peers:
        if not state.partitioned:
            alerts.append(Alert("critical", "node partitioned",
                                f"connected peers dropped to {connected_peer_count} (min {min_peers}); churn detection suspended"))
        state.partitioned = True
    elif state.partitioned:
        alerts.append(Alert("info", "connectivity restored",
                            f"{connected_peer_count} peer(s) connected; churn baseline reset"))
        state.partitioned = False
        state.first_snapshot = True
        state.miss_counts = {}
    return alerts


def detect_node_events(state: SamCopState, node_events: List[dict], latest_seq: int) -> List[Alert]:
    alerts = []
    # Tally flood-prone event types per peer so N events collapse into one alert; other types alert one-to-one.
    counts_by_type_and_peer: Dict[str, Dict[str, int]] = {event_type: {} for event_type in AGGREGATED_EVENT_TYPES}
    for event in node_events:
        event_type = event.get("type", "")
        if event_type in counts_by_type_and_peer:
            peer_id = event.get("peer_id", "")
            counts_by_type_and_peer[event_type][peer_id] = counts_by_type_and_peer[event_type].get(peer_id, 0) + 1
            continue
        severity = SEVERITY_BY_EVENT_TYPE.get(event_type, "info")
        alerts.append(Alert(severity, f"node event: {event_type}",
                            event.get("message", ""), peer_id=event.get("peer_id", "")))
    for peer_id, count in counts_by_type_and_peer["rate_limit_drop"].items():
        alerts.append(Alert("warning", "node event: rate_limit_drop",
                            f"{count} message(s) dropped this cycle", peer_id=peer_id))
    for peer_id, count in counts_by_type_and_peer["spoofing_attempt"].items():
        alerts.append(Alert("critical", "node event: spoofing_attempt",
                            f"{count} spoofing attempt(s) (invalid event signature) this cycle", peer_id=peer_id))
    for peer_id, count in counts_by_type_and_peer["stale_event"].items():
        alerts.append(Alert("warning", "node event: stale_event",
                            f"{count} stale event(s) this cycle", peer_id=peer_id))
    if state.cursor > 0 and latest_seq - state.cursor > len(node_events):
        lost = latest_seq - state.cursor - len(node_events)
        alerts.append(Alert("warning", "node event buffer wrapped",
                            f"~{lost} node event(s) lost before this poll"))
    state.cursor = latest_seq
    return alerts


def detect_churn(state: SamCopState, services_snapshot: set, miss_threshold: int) -> List[Alert]:
    if state.partitioned:
        return []
    if state.first_snapshot:
        state.baseline = set(services_snapshot)
        state.miss_counts = {}
        state.first_snapshot = False
        return []

    alerts = []
    for entry in sorted(services_snapshot - state.baseline):
        service_type, service_name, peer_id = entry
        alerts.append(Alert("info", "service appeared", f"{service_type}/{service_name} advertised on the mesh",
                            peer_id=peer_id, service=f"{service_type}/{service_name}"))
        state.baseline.add(entry)
    for entry in list(state.miss_counts):
        if entry in services_snapshot:
            del state.miss_counts[entry]
    for entry in sorted(state.baseline - services_snapshot):
        misses = state.miss_counts.get(entry, 0) + 1
        if misses >= miss_threshold:
            service_type, service_name, peer_id = entry
            alerts.append(Alert("warning", "service disappeared",
                                f"{service_type}/{service_name} missing for {misses} consecutive polls",
                                peer_id=peer_id, service=f"{service_type}/{service_name}"))
            state.baseline.discard(entry)
            state.miss_counts.pop(entry, None)
        else:
            state.miss_counts[entry] = misses
    return alerts


def evaluate_cycle(state: SamCopState, connected_peer_count: int, node_events: List[dict],
                   latest_seq: int, services_snapshot: set, config: SamCopConfig):
    alerts = []
    alerts.extend(detect_partition(state, connected_peer_count, config.min_peers))
    alerts.extend(detect_node_events(state, node_events, latest_seq))
    alerts.extend(detect_churn(state, services_snapshot, config.miss_threshold))
    return state, alerts


SERVICE_TYPES = ["mcp", "inference"]
DISCOVERY_PAGE_LIMIT = 200


def parse_tool_json(result) -> Optional[Any]:
    if result.get("isError"):
        content = result.get("content") or []
        detail = content[0].get("text", "") if content else repr(result)
        raise RuntimeError(f"tool error: {detail}")
    content = result.get("content") or []
    if not content:
        return None
    text = content[0].get("text", "")
    if not text:
        return None
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        return None


async def fetch_services(client) -> set:
    snapshot = set()
    for service_type in SERVICE_TYPES:
        offset = 0
        while True:
            result = await client.call_tool("discover_remote_services",
                                            {"type": service_type, "limit": DISCOVERY_PAGE_LIMIT, "offset": offset})
            providers = parse_tool_json(result) or []
            for provider in providers:
                snapshot.add((service_type, provider.get("srv_name", ""), provider.get("peer_id", "")))
            if len(providers) < DISCOVERY_PAGE_LIMIT:
                break
            offset += DISCOVERY_PAGE_LIMIT
    return snapshot


async def run_cycle(client, state: SamCopState, channels: List[Channel], config: SamCopConfig, node_peer_id: str) -> SamCopState:
    mesh_info = parse_tool_json(await client.call_tool("get_mesh_info", {})) or {}
    connected_peer_count = len(mesh_info.get("connected_peers") or [])

    events_response = parse_tool_json(await client.call_tool("poll_node_events", {"since_seq": state.cursor})) or {}
    node_events = events_response.get("events") or []
    latest_seq = events_response.get("latest_seq", state.cursor)

    services_snapshot = await fetch_services(client)

    state, alerts = evaluate_cycle(state, connected_peer_count, node_events, latest_seq, services_snapshot, config)

    timestamp = datetime.now(timezone.utc).isoformat(timespec="seconds")
    for alert in alerts:
        await deliver(channels, format_alert(alert, node_peer_id, timestamp))
    return state


async def connect_with_retry(retries: int = 12, delay: float = 5.0) -> SamClient:
    for attempt in range(1, retries + 1):
        client = SamClient()
        try:
            await client.connect()
            return client
        except Exception as error:
            if attempt == retries:
                raise
            print(f"[-] Failed to connect to SAM node (attempt {attempt}/{retries}): {error}. "
                  f"Retrying in {delay} seconds...", flush=True)
            await asyncio.sleep(delay)


CONSECUTIVE_FAILURE_LIMIT = 3


async def reconnect(client, state: SamCopState) -> Tuple[SamClient, str, SamCopState]:
    """Recovers from a lost MCP session; the node's seq counter restarts too, so reset cursor."""
    try:
        await client.close()
    except Exception as error:
        print(f"[-] error closing stale client: {error}", flush=True)
    client = await connect_with_retry()
    mesh_info = parse_tool_json(await client.call_tool("get_mesh_info", {})) or {}
    node_peer_id = mesh_info.get("peer_id", "unknown")
    state.cursor = 0
    return client, node_peer_id, state


async def run_sam_cop():
    config = load_config(os.environ)
    channels = build_channels(os.environ)
    channel_names = ", ".join(channel.name for channel in channels)
    print(f"[*] sam-cop starting: poll={config.poll_interval}s miss_threshold={config.miss_threshold} "
          f"min_peers={config.min_peers} channels=[{channel_names}]", flush=True)

    client = await connect_with_retry()
    try:
        mesh_info = parse_tool_json(await client.call_tool("get_mesh_info", {})) or {}
        node_peer_id = mesh_info.get("peer_id", "unknown")
        print(f"[+] connected to local node {node_peer_id}", flush=True)

        state = SamCopState()
        consecutive_failures = 0
        while True:
            try:
                state = await run_cycle(client, state, channels, config, node_peer_id)
                consecutive_failures = 0
            except Exception as error:
                consecutive_failures += 1
                print(f"[-] poll cycle failed ({consecutive_failures}/{CONSECUTIVE_FAILURE_LIMIT}): {error}", flush=True)
                if consecutive_failures >= CONSECUTIVE_FAILURE_LIMIT:
                    print("[-] too many consecutive failures, reconnecting to SAM node", flush=True)
                    client, node_peer_id, state = await reconnect(client, state)
                    consecutive_failures = 0
                    print(f"[+] reconnected to local node {node_peer_id}", flush=True)
            await asyncio.sleep(config.poll_interval)
    finally:
        await client.close()


if __name__ == "__main__":
    try:
        asyncio.run(run_sam_cop())
    except KeyboardInterrupt:
        sys.exit(0)
