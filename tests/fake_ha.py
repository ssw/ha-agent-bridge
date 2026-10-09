"""A fake Home Assistant serving a scenario house over real HTTP and WebSocket.

It implements just the REST and WebSocket endpoints the bridge uses, checks
the bearer token like HA does, and records every service call and event.
"""

from __future__ import annotations

import socket
import threading
import time
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any

import uvicorn
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.routing import Route, WebSocketRoute
from starlette.websockets import WebSocket, WebSocketDisconnect

HA_TOKEN = "ha-token-for-muse-bridge"


@dataclass
class Entity:
    entity_id: str
    state: str
    platform: str
    area_id: str | None = None
    attributes: dict[str, Any] = field(default_factory=dict)
    hidden: bool = False
    device_id: str | None = None
    category: str | None = None  # entity_category: diagnostic / config


@dataclass
class House:
    """A scenario: rooms, entities, history and logbook, anchored to `now`."""

    now: datetime
    areas: dict[str, str]
    entities: list[Entity]
    history: dict[str, list[tuple[datetime, str]]] = field(default_factory=dict)
    statistics: dict[str, list[dict[str, Any]]] = field(default_factory=dict)
    logbook: list[dict[str, Any]] = field(default_factory=list)
    device_areas: dict[str, str] = field(default_factory=dict)


class FakeHA:
    def __init__(self, house: House) -> None:
        self.house = house
        self.calls: list[tuple[str, dict[str, Any]]] = []
        self.events: list[tuple[str, dict[str, Any]]] = []
        self.port = _free_port()
        self.url = f"http://127.0.0.1:{self.port}"
        self._server: uvicorn.Server | None = None

    # --- lifecycle --------------------------------------------------------------

    def start(self) -> None:
        config = uvicorn.Config(
            self._app(), host="127.0.0.1", port=self.port, log_level="warning"
        )
        self._server = uvicorn.Server(config)
        threading.Thread(target=self._server.run, daemon=True).start()
        deadline = time.monotonic() + 10
        while not self._server.started:
            if time.monotonic() > deadline:
                raise RuntimeError("fake HA did not start")
            time.sleep(0.02)

    def stop(self) -> None:
        if self._server:
            self._server.should_exit = True

    def reset(self) -> None:
        self.calls.clear()
        self.events.clear()

    def service_calls(self, name: str) -> list[dict[str, Any]]:
        return [data for svc, data in self.calls if svc == name]

    # --- HTTP -------------------------------------------------------------------

    def _authorized(self, request: Request) -> bool:
        return request.headers.get("authorization") == f"Bearer {HA_TOKEN}"

    def _state(self, e: Entity) -> dict[str, Any]:
        changed = self.house.now - timedelta(minutes=5)
        return {
            "entity_id": e.entity_id,
            "state": e.state,
            "attributes": e.attributes,
            "last_changed": changed.isoformat(),
            "last_updated": changed.isoformat(),
        }

    def _app(self) -> Starlette:
        async def guard(request: Request, handler) -> Response:
            if not self._authorized(request):
                return JSONResponse({"message": "Unauthorized"}, status_code=401)
            return await handler(request)

        async def config(request: Request) -> Response:
            return await guard(
                request,
                lambda _: _json(
                    {"time_zone": "America/Los_Angeles", "version": "fake"}
                ),
            )

        async def states(request: Request) -> Response:
            return await guard(
                request, lambda _: _json([self._state(e) for e in self.house.entities])
            )

        async def one_state(request: Request) -> Response:
            async def handle(_: Request) -> Response:
                wanted = request.path_params["entity_id"]
                for e in self.house.entities:
                    if e.entity_id == wanted:
                        return JSONResponse(self._state(e))
                return JSONResponse({"message": "Entity not found."}, status_code=404)

            return await guard(request, handle)

        async def history(request: Request) -> Response:
            async def handle(_: Request) -> Response:
                start = datetime.fromisoformat(request.path_params["start"])
                end = datetime.fromisoformat(request.query_params["end_time"])
                entity_id = request.query_params["filter_entity_id"]
                points = self.house.history.get(entity_id, [])
                # Like HA: the state in force at `start`, then changes in range.
                before = [p for p in points if p[0] <= start]
                inside = [p for p in points if start < p[0] <= end]
                rows = ([(start, before[-1][1])] if before else []) + inside
                return JSONResponse(
                    [
                        [
                            {
                                "entity_id": entity_id,
                                "state": s,
                                "last_changed": t.isoformat(),
                            }
                            for t, s in rows
                        ]
                    ]
                    if rows
                    else []
                )

            return await guard(request, handle)

        async def logbook(request: Request) -> Response:
            return await guard(request, lambda _: _json(self.house.logbook))

        async def service(request: Request) -> Response:
            async def handle(_: Request) -> Response:
                name = (
                    f"{request.path_params['domain']}.{request.path_params['service']}"
                )
                self.calls.append((name, await request.json()))
                return JSONResponse([])

            return await guard(request, handle)

        async def event(request: Request) -> Response:
            async def handle(_: Request) -> Response:
                self.events.append(
                    (request.path_params["event_type"], await request.json())
                )
                return JSONResponse({"message": "Event fired."})

            return await guard(request, handle)

        async def websocket(ws: WebSocket) -> None:
            await ws.accept()
            await ws.send_json({"type": "auth_required"})
            auth = await ws.receive_json()
            if auth.get("access_token") != HA_TOKEN:
                await ws.send_json({"type": "auth_invalid"})
                await ws.close()
                return
            await ws.send_json({"type": "auth_ok"})
            while True:
                try:
                    msg = await ws.receive_json()
                except WebSocketDisconnect:
                    return
                await ws.send_json(
                    {
                        "id": msg["id"],
                        "type": "result",
                        "success": True,
                        "result": self._ws(msg),
                    }
                )

        return Starlette(
            routes=[
                Route("/api/config", config),
                Route("/api/states", states),
                Route("/api/states/{entity_id}", one_state),
                Route("/api/history/period/{start:path}", history),
                Route("/api/logbook/{start:path}", logbook),
                Route("/api/services/{domain}/{service}", service, methods=["POST"]),
                Route("/api/events/{event_type}", event, methods=["POST"]),
                WebSocketRoute("/api/websocket", websocket),
            ]
        )

    def _ws(self, msg: dict[str, Any]) -> Any:
        kind = msg["type"]
        if kind == "config/area_registry/list":
            return [{"area_id": a, "name": n} for a, n in self.house.areas.items()]
        if kind == "config/device_registry/list":
            return [{"id": d, "area_id": a} for d, a in self.house.device_areas.items()]
        if kind == "config/entity_registry/list":
            return [
                {
                    "entity_id": e.entity_id,
                    "platform": e.platform,
                    "area_id": e.area_id,
                    "device_id": e.device_id,
                    "hidden_by": "user" if e.hidden else None,
                    "entity_category": e.category,
                }
                for e in self.house.entities
            ]
        if kind == "recorder/statistics_during_period":
            start = datetime.fromisoformat(msg["start_time"])
            end = datetime.fromisoformat(msg["end_time"])
            out = {}
            for statistic_id in msg["statistic_ids"]:
                rows = self.house.statistics.get(statistic_id, [])
                out[statistic_id] = [
                    r
                    for r in rows
                    if start.timestamp() * 1000 <= r["start"] < end.timestamp() * 1000
                ]
            return out
        raise ValueError(f"fake HA doesn't implement {kind}")


async def _json_async(value: Any) -> Response:
    return JSONResponse(value)


def _json(value: Any):
    return _json_async(value)


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def at(now: datetime, **delta: float) -> datetime:
    return (now + timedelta(**delta)).astimezone(UTC)
