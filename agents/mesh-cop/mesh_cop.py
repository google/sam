import abc
import asyncio
import json
import os
import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Dict, List, Optional, Any

import httpx
from mcp import ClientSession
from mcp.client.streamable_http import streamable_http_client


class SamClient:
    """Inlined SAM Client for self-contained execution."""
    def __init__(self, server_url: Optional[str] = None, token: Optional[str] = None):
        if server_url is None:
            server_url = os.environ.get("SAM_MCP_URL", "http://localhost:8080/mcp")
        if token is None:
            token = os.environ.get("SAM_API_TOKEN")
        self.server_url = server_url
        self.token = token
        self.session: Optional[ClientSession] = None
        self._sse_cm = None
        self.lock = asyncio.Lock()

    async def connect(self):
        headers = {"Accept": "application/json, text/event-stream"}
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        self._sse_cm = streamable_http_client(self.server_url, headers=headers)
        read_stream, write_stream, _ = await self._sse_cm.__aenter__()
        self.session = ClientSession(read_stream, write_stream)
        await self.session.__aenter__()
        await self.session.initialize()

    async def close(self):
        if self.session:
            await self.session.__aexit__(None, None, None)
        if self._sse_cm:
            await self._sse_cm.__aexit__(None, None, None)
        self.session = None
        self._sse_cm = None

    async def get_tools(self) -> List[Dict[str, Any]]:
        if not self.session:
            raise RuntimeError("Not connected")
        async with self.lock:
            resp = await self.session.list_tools()
            return [t.model_dump() if hasattr(t, "model_dump") else t for t in resp.tools]

    async def call_tool(self, name: str, arguments: Dict[str, Any]) -> Dict[str, Any]:
        if not self.session:
            raise RuntimeError("Not connected")
        async with self.lock:
            resp = await self.session.call_tool(name, arguments)
            return resp.model_dump() if hasattr(resp, "model_dump") else resp

    async def __aenter__(self):
        for attempt in range(1, 13):
            try:
                await self.connect()
                return self
            except Exception as e:
                if attempt == 12:
                    raise
                print(f"[-] Failed to connect to SAM node (attempt {attempt}/12): {e}. Retrying in 5 seconds...")
                await asyncio.sleep(5.0)
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.close()


@dataclass
class CopConfig:
    poll_interval: float
    miss_threshold: int
    min_peers: int


def load_config(env) -> CopConfig:
    return CopConfig(
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


def format_alert(alert: Alert, node_peer_id: str, timestamp: str) -> str:
    lines = [f"{SEVERITY_EMOJI[alert.severity]} [{alert.severity.upper()}] {alert.title}"]
    if alert.description:
        lines.append(alert.description)
    if alert.peer_id:
        lines.append(f"peer: {alert.peer_id}")
    if alert.service:
        lines.append(f"service: {alert.service}")
    lines.append(f"reported by {node_peer_id} at {timestamp}")
    return "\n".join(lines)


class Channel(abc.ABC):
    """Delivery backend. Implement send() and add one entry in build_channels()."""

    name = "channel"

    @abc.abstractmethod
    async def send(self, message: str) -> None: ...


class SlackChannel(Channel):
    name = "slack"

    def __init__(self, webhook_url: str):
        self.webhook_url = webhook_url

    async def send(self, message: str) -> None:
        async with httpx.AsyncClient() as http_client:
            response = await http_client.post(self.webhook_url, json={"text": message}, timeout=10.0)
            response.raise_for_status()


class TelegramChannel(Channel):
    name = "telegram"

    def __init__(self, bot_token: str, chat_id: str):
        self.bot_token = bot_token
        self.chat_id = chat_id

    async def send(self, message: str) -> None:
        url = f"https://api.telegram.org/bot{self.bot_token}/sendMessage"
        async with httpx.AsyncClient() as http_client:
            response = await http_client.post(url, json={"chat_id": self.chat_id, "text": message}, timeout=10.0)
            response.raise_for_status()


class StdoutChannel(Channel):
    name = "stdout"

    async def send(self, message: str) -> None:
        print(f"[ALERT] {message}", flush=True)


def build_channels(env) -> List[Channel]:
    channels: List[Channel] = []
    if env.get("SLACK_WEBHOOK_URL"):
        channels.append(SlackChannel(env["SLACK_WEBHOOK_URL"]))
    if env.get("TELEGRAM_BOT_TOKEN") and env.get("TELEGRAM_CHAT_ID"):
        channels.append(TelegramChannel(env["TELEGRAM_BOT_TOKEN"], env["TELEGRAM_CHAT_ID"]))
    if not channels:
        channels.append(StdoutChannel())
    return channels


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


@dataclass
class CopState:
    cursor: int = 0
    baseline: set = field(default_factory=set)
    miss_counts: dict = field(default_factory=dict)
    partitioned: bool = False
    first_snapshot: bool = True


def detect_partition(state: CopState, connected_peer_count: int, min_peers: int) -> List[Alert]:
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


def detect_node_events(state: CopState, node_events: List[dict], latest_seq: int) -> List[Alert]:
    alerts = []
    rate_limit_drops_by_peer: Dict[str, int] = {}
    for event in node_events:
        event_type = event.get("type", "")
        if event_type == "rate_limit_drop":
            peer_id = event.get("peer_id", "")
            rate_limit_drops_by_peer[peer_id] = rate_limit_drops_by_peer.get(peer_id, 0) + 1
            continue
        severity = SEVERITY_BY_EVENT_TYPE.get(event_type, "info")
        alerts.append(Alert(severity, f"node event: {event_type}",
                            event.get("message", ""), peer_id=event.get("peer_id", "")))
    for peer_id, count in rate_limit_drops_by_peer.items():
        alerts.append(Alert("warning", "node event: rate_limit_drop",
                            f"{count} message(s) dropped this cycle", peer_id=peer_id))
    if state.cursor > 0 and latest_seq - state.cursor > len(node_events):
        lost = latest_seq - state.cursor - len(node_events)
        alerts.append(Alert("warning", "node event buffer wrapped",
                            f"~{lost} node event(s) lost before this poll"))
    state.cursor = latest_seq
    return alerts


def detect_churn(state: CopState, services_snapshot: set, miss_threshold: int) -> List[Alert]:
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


def evaluate_cycle(state: CopState, connected_peer_count: int, node_events: List[dict],
                   latest_seq: int, services_snapshot: set, config: CopConfig):
    alerts = []
    alerts.extend(detect_partition(state, connected_peer_count, config.min_peers))
    alerts.extend(detect_node_events(state, node_events, latest_seq))
    alerts.extend(detect_churn(state, services_snapshot, config.miss_threshold))
    return state, alerts


SERVICE_TYPES = ["mcp", "inference"]
DISCOVERY_PAGE_LIMIT = 200


def parse_tool_json(result) -> Optional[Any]:
    text = result.get("content", [{}])[0].get("text", "")
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


async def run_cycle(client, state: CopState, channels: List[Channel], config: CopConfig, node_peer_id: str) -> CopState:
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


async def run_mesh_cop():
    config = load_config(os.environ)
    channels = build_channels(os.environ)
    channel_names = ", ".join(channel.name for channel in channels)
    print(f"[*] mesh-cop starting: poll={config.poll_interval}s miss_threshold={config.miss_threshold} "
          f"min_peers={config.min_peers} channels=[{channel_names}]", flush=True)

    async with SamClient() as client:
        mesh_info = parse_tool_json(await client.call_tool("get_mesh_info", {})) or {}
        node_peer_id = mesh_info.get("peer_id", "unknown")
        print(f"[+] connected to local node {node_peer_id}", flush=True)

        state = CopState()
        while True:
            try:
                state = await run_cycle(client, state, channels, config, node_peer_id)
            except Exception as error:
                print(f"[-] poll cycle failed: {error}", flush=True)
            await asyncio.sleep(config.poll_interval)


if __name__ == "__main__":
    try:
        asyncio.run(run_mesh_cop())
    except KeyboardInterrupt:
        sys.exit(0)
