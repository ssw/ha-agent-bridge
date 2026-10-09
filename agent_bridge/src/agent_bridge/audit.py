"""Audit log lines, HA events for writes, and throttled alerts."""

from __future__ import annotations

import json
import logging
import time
from typing import Any

from .ha import HA, HAError

log = logging.getLogger("agent_bridge.audit")

EVENT_TYPE = "agent_bridge_call"
ALERT_INTERVAL_S = 300  # at most one alert per kind per 5 minutes


class Audit:
    def __init__(self, ha: HA, alert_service: str) -> None:
        self._ha = ha
        self._alert_domain, _, self._alert_service = alert_service.partition(".")
        self._last_alert: dict[str, float] = {}

    def record(self, **fields: Any) -> None:
        """One JSON line per request. Never pass tokens or secrets here."""
        log.info(json.dumps(fields, sort_keys=True, default=str))

    async def write_event(self, **fields: Any) -> None:
        try:
            await self._ha.fire_event(EVENT_TYPE, fields)
        except HAError as err:
            log.warning("could not fire %s: %s", EVENT_TYPE, err)

    async def alert(self, kind: str, message: str) -> None:
        now = time.monotonic()
        if now - self._last_alert.get(kind, -ALERT_INTERVAL_S) < ALERT_INTERVAL_S:
            return
        self._last_alert[kind] = now
        try:
            await self._ha.call_service(
                self._alert_domain,
                self._alert_service,
                {"title": "Agent Bridge", "message": message},
            )
        except HAError as err:
            log.warning("could not send alert: %s", err)
