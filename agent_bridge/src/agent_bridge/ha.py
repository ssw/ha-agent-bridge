"""A small Home Assistant client: REST for states, history, logbook and
services; WebSocket for the registries and recorder statistics."""

from __future__ import annotations

import json
import time
from dataclasses import dataclass
from datetime import datetime
from typing import Any

import httpx
import websockets

REGISTRY_TTL_S = 60


class HAError(Exception):
    """Home Assistant returned an error or could not be reached."""


@dataclass(frozen=True)
class Catalog:
    """Registry data needed to name, place and filter entities."""

    areas: dict[str, str]  # area_id -> name
    entity_area: dict[str, str]  # entity_id -> area_id (entity's own, else device's)
    entity_integration: dict[str, str]  # entity_id -> integration (platform)
    hidden: frozenset[str]  # entities hidden in HA

    def area_id_for(self, name_or_id: str) -> str | None:
        if name_or_id in self.areas:
            return name_or_id
        wanted = name_or_id.strip().casefold()
        for area_id, name in self.areas.items():
            if name.casefold() == wanted:
                return area_id
        return None

    def entities_in(self, area_id: str) -> list[str]:
        return sorted(e for e, a in self.entity_area.items() if a == area_id)


class HA:
    def __init__(self, url: str, token: str, timeout: float = 15.0) -> None:
        self._url = url.rstrip("/")
        self._token = token
        self._http = httpx.AsyncClient(
            base_url=self._url,
            headers={"Authorization": f"Bearer {token}"},
            timeout=timeout,
        )
        self._catalog: Catalog | None = None
        self._catalog_at = 0.0

    async def close(self) -> None:
        await self._http.aclose()

    # --- REST ---------------------------------------------------------------

    async def _get(self, path: str, params: dict[str, Any] | None = None) -> Any:
        try:
            resp = await self._http.get(path, params=params)
        except httpx.HTTPError as err:
            raise HAError(f"Home Assistant unreachable: {err}") from err
        if resp.status_code == 404:
            return None
        if resp.status_code >= 400:
            raise HAError(f"Home Assistant returned {resp.status_code} for GET {path}")
        return resp.json()

    async def _post(self, path: str, body: dict[str, Any]) -> Any:
        try:
            resp = await self._http.post(path, json=body)
        except httpx.HTTPError as err:
            raise HAError(f"Home Assistant unreachable: {err}") from err
        if resp.status_code >= 400:
            detail = resp.text[:300]
            raise HAError(f"Home Assistant returned {resp.status_code}: {detail}")
        return resp.json() if resp.content else None

    async def config(self) -> dict[str, Any]:
        return await self._get("/api/config")

    async def states(self) -> list[dict[str, Any]]:
        return await self._get("/api/states") or []

    async def state(self, entity_id: str) -> dict[str, Any] | None:
        return await self._get(f"/api/states/{entity_id}")

    async def history(
        self, entity_id: str, start: datetime, end: datetime
    ) -> list[dict[str, Any]]:
        result = await self._get(
            f"/api/history/period/{start.isoformat()}",
            {
                "filter_entity_id": entity_id,
                "end_time": end.isoformat(),
                "minimal_response": "",
                "no_attributes": "",
            },
        )
        return result[0] if result else []

    async def logbook(
        self, start: datetime, end: datetime, entity_id: str | None = None
    ) -> list[dict[str, Any]]:
        params: dict[str, Any] = {"end_time": end.isoformat()}
        if entity_id:
            params["entity"] = entity_id
        return await self._get(f"/api/logbook/{start.isoformat()}", params) or []

    async def call_service(
        self, domain: str, service: str, data: dict[str, Any]
    ) -> list[dict[str, Any]]:
        return await self._post(f"/api/services/{domain}/{service}", data) or []

    async def fire_event(self, event_type: str, data: dict[str, Any]) -> None:
        await self._post(f"/api/events/{event_type}", data)

    # --- WebSocket ------------------------------------------------------------

    async def _ws(self, *commands: dict[str, Any]) -> list[Any]:
        url = self._url.replace("http", "ws", 1) + "/api/websocket"
        try:
            async with websockets.connect(url, max_size=None) as ws:
                await ws.recv()  # auth_required
                await ws.send(json.dumps({"type": "auth", "access_token": self._token}))
                auth = json.loads(await ws.recv())
                if auth.get("type") != "auth_ok":
                    raise HAError("Home Assistant rejected the bridge's token")
                results = []
                for msg_id, command in enumerate(commands, start=1):
                    await ws.send(json.dumps({"id": msg_id, **command}))
                    while True:
                        reply = json.loads(await ws.recv())
                        if reply.get("id") == msg_id and reply.get("type") == "result":
                            break
                    if not reply.get("success"):
                        raise HAError(f"{command['type']}: {reply.get('error')}")
                    results.append(reply["result"])
                return results
        except (OSError, websockets.WebSocketException) as err:
            raise HAError(f"Home Assistant unreachable: {err}") from err

    async def catalog(self) -> Catalog:
        if self._catalog and time.monotonic() - self._catalog_at < REGISTRY_TTL_S:
            return self._catalog
        areas, devices, entities = await self._ws(
            {"type": "config/area_registry/list"},
            {"type": "config/device_registry/list"},
            {"type": "config/entity_registry/list"},
        )
        device_area = {d["id"]: d.get("area_id") for d in devices}
        entity_area = {}
        for e in entities:
            area = e.get("area_id") or device_area.get(e.get("device_id"))
            if area:
                entity_area[e["entity_id"]] = area
        self._catalog = Catalog(
            areas={a["area_id"]: a["name"] for a in areas},
            entity_area=entity_area,
            entity_integration={e["entity_id"]: e.get("platform") for e in entities},
            hidden=frozenset(e["entity_id"] for e in entities if e.get("hidden_by")),
        )
        self._catalog_at = time.monotonic()
        return self._catalog

    async def statistics(
        self, entity_id: str, start: datetime, end: datetime, period: str
    ) -> list[dict[str, Any]]:
        (result,) = await self._ws(
            {
                "type": "recorder/statistics_during_period",
                "start_time": start.isoformat(),
                "end_time": end.isoformat(),
                "statistic_ids": [entity_id],
                "period": period,
                "types": ["mean", "min", "max"],
            }
        )
        return result.get(entity_id, [])
