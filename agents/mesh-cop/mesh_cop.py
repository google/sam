import abc
import asyncio
from dataclasses import dataclass
from typing import List

import httpx


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
