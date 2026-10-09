"""Settings, from the add-on's /data/options.json or the environment."""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from pathlib import Path

OPTIONS_PATH = Path("/data/options.json")


@dataclass(frozen=True)
class Settings:
    ha_url: str
    ha_token: str
    policy: str
    public_url: str = "http://localhost:8099"
    alert_service: str = "persistent_notification.create"
    log_level: str = "info"
    listen_host: str = "127.0.0.1"
    listen_port: int = 8099


def load() -> Settings:
    options = json.loads(OPTIONS_PATH.read_text()) if OPTIONS_PATH.exists() else {}

    def get(key: str, default: str = "") -> str:
        return os.environ.get(f"AGENT_BRIDGE_{key.upper()}", options.get(key, default))

    return Settings(
        ha_url=get("ha_url", "http://homeassistant:8123"),
        ha_token=get("ha_token"),
        policy=get("policy"),
        public_url=get("public_url", "http://localhost:8099"),
        alert_service=get("alert_service", "persistent_notification.create"),
        log_level=get("log_level", "info"),
    )
