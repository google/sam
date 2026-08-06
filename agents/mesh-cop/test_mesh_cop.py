import asyncio
import json

from mesh_cop import (
    Alert,
    Channel,
    SlackChannel,
    StdoutChannel,
    TelegramChannel,
    build_channels,
    deliver,
    format_alert,
    load_config,
)


def test_load_config_defaults():
    config = load_config({})
    assert config.poll_interval == 30.0
    assert config.miss_threshold == 3
    assert config.min_peers == 1


def test_load_config_overrides():
    config = load_config({"POLL_INTERVAL": "5", "MISS_THRESHOLD": "2", "MIN_PEERS": "0"})
    assert config.poll_interval == 5.0
    assert config.miss_threshold == 2
    assert config.min_peers == 0


def test_build_channels_stdout_fallback():
    channels = build_channels({})
    assert len(channels) == 1
    assert isinstance(channels[0], StdoutChannel)


def test_build_channels_slack_and_telegram():
    env = {
        "SLACK_WEBHOOK_URL": "https://hooks.slack.example/x",
        "TELEGRAM_BOT_TOKEN": "token",
        "TELEGRAM_CHAT_ID": "42",
    }
    channels = build_channels(env)
    assert {type(c) for c in channels} == {SlackChannel, TelegramChannel}


def test_build_channels_telegram_requires_chat_id():
    channels = build_channels({"TELEGRAM_BOT_TOKEN": "token"})
    assert len(channels) == 1
    assert isinstance(channels[0], StdoutChannel)


def test_format_alert():
    alert = Alert("critical", "node event: banned", "peer banned by hub", peer_id="12D3KooPeer")
    message = format_alert(alert, "12D3KooSelf", "2026-08-06T10:00:00+00:00")
    assert message.startswith("🚨 [CRITICAL] node event: banned")
    assert "peer banned by hub" in message
    assert "peer: 12D3KooPeer" in message
    assert "reported by 12D3KooSelf at 2026-08-06T10:00:00+00:00" in message


class FlakyChannel(Channel):
    name = "flaky"

    def __init__(self, failures):
        self.failures = failures
        self.attempts = 0
        self.delivered = []

    async def send(self, message):
        self.attempts += 1
        if self.attempts <= self.failures:
            raise RuntimeError("boom")
        self.delivered.append(message)


def test_deliver_retries_then_succeeds():
    channel = FlakyChannel(failures=2)
    asyncio.run(deliver([channel], "hello"))
    assert channel.delivered == ["hello"]
    assert channel.attempts == 3


def test_deliver_gives_up_without_raising():
    channel = FlakyChannel(failures=5)
    asyncio.run(deliver([channel], "hello"))
    assert channel.delivered == []
    assert channel.attempts == 3


from mesh_cop import CopConfig, CopState, evaluate_cycle

CONFIG = CopConfig(poll_interval=30.0, miss_threshold=3, min_peers=1)
SERVICE_A = ("mcp", "service-a", "peer-1")
SERVICE_B = ("inference", "service-b", "peer-2")


def cycle(state, peers=2, events=None, latest_seq=None, snapshot=frozenset()):
    events = events or []
    if latest_seq is None:
        latest_seq = state.cursor + len(events)
    return evaluate_cycle(state, peers, events, latest_seq, set(snapshot), CONFIG)


def test_first_snapshot_sets_baseline_without_alerts():
    state, alerts = cycle(CopState(), snapshot={SERVICE_A})
    assert alerts == []
    assert state.baseline == {SERVICE_A}


def test_service_appeared_alerts_immediately():
    state, _ = cycle(CopState(), snapshot={SERVICE_A})
    state, alerts = cycle(state, snapshot={SERVICE_A, SERVICE_B})
    assert [a.severity for a in alerts] == ["info"]
    assert "appeared" in alerts[0].title
    assert SERVICE_B in state.baseline


def test_service_disappeared_needs_consecutive_misses():
    state, _ = cycle(CopState(), snapshot={SERVICE_A})
    state, alerts = cycle(state, snapshot=set())
    assert alerts == []
    state, alerts = cycle(state, snapshot=set())
    assert alerts == []
    state, alerts = cycle(state, snapshot=set())
    assert [a.severity for a in alerts] == ["warning"]
    assert "disappeared" in alerts[0].title
    assert SERVICE_A not in state.baseline


def test_reappearing_service_resets_miss_count():
    state, _ = cycle(CopState(), snapshot={SERVICE_A})
    state, _ = cycle(state, snapshot=set())
    state, _ = cycle(state, snapshot={SERVICE_A})
    state, alerts = cycle(state, snapshot=set())
    assert alerts == []


def test_partition_alerts_once_and_suppresses_churn():
    state, _ = cycle(CopState(), snapshot={SERVICE_A})
    state, alerts = cycle(state, peers=0, snapshot=set())
    assert [a.severity for a in alerts] == ["critical"]
    state, alerts = cycle(state, peers=0, snapshot=set())
    assert alerts == []
    assert state.baseline == {SERVICE_A}
    assert state.miss_counts == {}


def test_partition_recovery_resets_baseline():
    state, _ = cycle(CopState(), snapshot={SERVICE_A})
    state, _ = cycle(state, peers=0, snapshot=set())
    state, alerts = cycle(state, peers=2, snapshot={SERVICE_B})
    assert [a.severity for a in alerts] == ["info"]
    assert "restored" in alerts[0].title
    state, alerts = cycle(state, snapshot={SERVICE_B})
    assert alerts == []
    assert state.baseline == {SERVICE_B}


def test_node_event_severities():
    events = [
        {"seq": 1, "type": "banned", "peer_id": "p", "message": "m"},
        {"seq": 2, "type": "spoofing_attempt", "peer_id": "p", "message": "m"},
        {"seq": 3, "type": "policy_update", "peer_id": "", "message": "m"},
        {"seq": 4, "type": "key_rotation", "peer_id": "", "message": "m"},
    ]
    state, alerts = cycle(CopState(cursor=0, first_snapshot=False), events=events, latest_seq=4)
    assert [a.severity for a in alerts] == ["critical", "critical", "info", "warning"]
    assert state.cursor == 4


def test_rate_limit_drops_aggregate_per_peer():
    events = [
        {"seq": 1, "type": "rate_limit_drop", "peer_id": "p1", "message": "m"},
        {"seq": 2, "type": "rate_limit_drop", "peer_id": "p1", "message": "m"},
        {"seq": 3, "type": "rate_limit_drop", "peer_id": "p2", "message": "m"},
    ]
    _, alerts = cycle(CopState(first_snapshot=False), events=events, latest_seq=3)
    assert len(alerts) == 2
    assert all(a.severity == "warning" for a in alerts)
    descriptions = " | ".join(a.description for a in alerts)
    assert "2 message(s)" in descriptions and "1 message(s)" in descriptions


def test_event_loss_detected_after_first_poll():
    state = CopState(cursor=5, first_snapshot=False)
    state, alerts = cycle(state, events=[{"seq": 100, "type": "policy_update", "peer_id": "", "message": "m"}], latest_seq=100)
    severities = [a.severity for a in alerts]
    assert severities.count("warning") == 1
    assert any("buffer wrapped" in a.title for a in alerts)
    assert state.cursor == 100


def test_no_event_loss_alert_on_first_poll():
    _, alerts = cycle(CopState(first_snapshot=False), events=[], latest_seq=5000)
    assert alerts == []


from mesh_cop import fetch_services, parse_tool_json


def test_parse_tool_json():
    result = {"content": [{"text": '{"events": [], "latest_seq": 7}'}]}
    assert parse_tool_json(result) == {"events": [], "latest_seq": 7}


def test_parse_tool_json_empty_text():
    assert parse_tool_json({"content": [{"text": ""}]}) is None


class FakeSamClient:
    def __init__(self, pages):
        self.pages = pages
        self.calls = []

    async def call_tool(self, name, arguments):
        self.calls.append((name, arguments))
        service_type = arguments["type"]
        offset = arguments["offset"]
        providers = self.pages.get(service_type, [])[offset:offset + arguments["limit"]]
        return {"content": [{"text": json.dumps(providers)}]}


def test_fetch_services_paginates_and_builds_tuples():
    mcp_providers = [{"peer_id": f"peer-{i}", "srv_name": f"service-{i}"} for i in range(250)]
    client = FakeSamClient({"mcp": mcp_providers, "inference": [{"peer_id": "peer-x", "srv_name": "vllm"}]})
    snapshot = asyncio.run(fetch_services(client))
    assert ("inference", "vllm", "peer-x") in snapshot
    assert len(snapshot) == 251
    mcp_calls = [c for c in client.calls if c[1]["type"] == "mcp"]
    assert len(mcp_calls) == 2  # 250 providers, limit 200 → two pages
