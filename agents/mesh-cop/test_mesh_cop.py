import asyncio

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
