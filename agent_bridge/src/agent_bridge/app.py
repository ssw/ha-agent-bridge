"""The HTTP API agents call.

Every /v1 request is authenticated by an agent's bearer token, which selects a
named token, which selects a policy. Reads are filtered by that policy's read rules; writes are
checked entity by entity against its allow rules before anything reaches HA.
"""

# No `from __future__ import annotations`: FastAPI needs real annotation
# objects to resolve the `Agent` dependency defined inside create_app.
import time
from collections import deque
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from dataclasses import dataclass
from datetime import UTC, datetime, tzinfo
from typing import Annotated, Any
from zoneinfo import ZoneInfo

from fastapi import Depends, FastAPI, HTTPException, Path, Query, Request
from fastapi.responses import JSONResponse
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, Field

from . import history
from .audit import Audit
from .config import Settings
from .ha import HA, Catalog, HAError
from .policy import AccessConfig, AccessPolicy, Denied, Token, parse

# Attributes that are noise for an agent or duplicated elsewhere in the view.
DROPPED_ATTRIBUTES = {
    "friendly_name",
    "unit_of_measurement",
    "device_class",
    "icon",
    "entity_picture",
    "supported_features",
    "supported_color_modes",
    "attribution",
}
MAX_ATTRIBUTE_ITEMS = 20
MAX_ATTRIBUTE_CHARS = 200

DESCRIPTION = """\
Read and control a home through Home Assistant, within a fixed policy.

Typical flow: list areas, list entities in an area (optionally by domain),
then read history or call an allowed service. Times are local
(America/Los_Angeles unless the home says otherwise). Use `GET /v1/services`
to see exactly which actions are allowed, on which entities, with which values.
Requests outside the policy fail with 403 and a message saying what is allowed.
"""

bearer = HTTPBearer(
    auto_error=False, description="Agent token issued by the home owner"
)


class ServiceCall(BaseModel):
    entity_id: str | list[str] | None = Field(
        None,
        description="Entity or entities to act on, e.g. 'light.kitchen_island_pendant'.",
    )
    area: str | list[str] | None = Field(
        None,
        description=(
            "Area (room) name or id. Expands to that room's entities of the "
            "service's domain; entities the policy doesn't allow are skipped."
        ),
    )
    data: dict[str, Any] = Field(
        default_factory=dict,
        description="Service fields, e.g. {'brightness_pct': 40} or {'temperature': 70}.",
    )


@dataclass(frozen=True)
class Caller:
    """An authenticated request's token and the policy it gets."""

    token: Token
    policy: AccessPolicy

    def who(self) -> dict[str, str]:
        return {"token": self.token.name, "policy": self.policy.name}


class RateLimiter:
    def __init__(self) -> None:
        self._calls: dict[str, deque[float]] = {}

    def allow(self, key: str, per_hour: int) -> bool:
        now = time.monotonic()
        calls = self._calls.setdefault(key, deque())
        while calls and now - calls[0] > 3600:
            calls.popleft()
        if len(calls) >= per_hour:
            return False
        calls.append(now)
        return True


def create_app(settings: Settings) -> FastAPI:
    config: AccessConfig = parse(settings.policy)
    ha = HA(settings.ha_url, settings.ha_token)
    audit = Audit(ha, settings.alert_service)
    limiter = RateLimiter()
    state: dict[str, tzinfo] = {"tz": ZoneInfo("America/Los_Angeles")}

    @asynccontextmanager
    async def lifespan(_: FastAPI) -> AsyncIterator[None]:
        try:
            tz_name = (await ha.config()).get("time_zone")
            if tz_name:
                state["tz"] = ZoneInfo(tz_name)
        except HAError:
            pass  # keep the default; HA may still be starting
        yield
        await ha.close()

    app = FastAPI(
        title="Home bridge",
        version="0.3.0",
        description=DESCRIPTION,
        servers=[{"url": settings.public_url}],
        lifespan=lifespan,
        docs_url=None,
        redoc_url=None,
    )

    @app.exception_handler(HAError)
    async def ha_error(_: Request, err: HAError) -> JSONResponse:
        return JSONResponse(status_code=502, content={"detail": str(err)})

    async def agent(
        request: Request,
        creds: Annotated[HTTPAuthorizationCredentials | None, Depends(bearer)],
    ) -> Caller:
        token = config.token_for(creds.credentials) if creds else None
        if token is None:
            audit.record(event="auth_failed", path=request.url.path)
            await audit.alert(
                "auth_failed",
                f"Rejected a request with a bad token: {request.url.path}",
            )
            raise HTTPException(401, "missing or invalid token")
        caller = Caller(token, config.policy_for(token))
        if not config.active(token):
            audit.record(event="disabled", **caller.who(), path=request.url.path)
            raise HTTPException(403, "agent access is disabled")
        return caller

    Agent = Annotated[Caller, Depends(agent)]

    def tz() -> tzinfo:
        return state["tz"]

    def readable(caller: Caller, catalog: Catalog, entity_id: str) -> bool:
        return caller.policy.read.allows(
            entity_id, catalog.entity_integration.get(entity_id)
        )

    def view(raw: dict[str, Any], catalog: Catalog) -> dict[str, Any]:
        entity_id = raw["entity_id"]
        attrs = raw.get("attributes", {})
        area_id = catalog.entity_area.get(entity_id)
        out = {
            "entity_id": entity_id,
            "name": attrs.get("friendly_name", entity_id),
            "area": catalog.areas.get(area_id) if area_id else None,
            "state": raw.get("state"),
            "unit": attrs.get("unit_of_measurement"),
            "device_class": attrs.get("device_class"),
            "last_changed": _local(raw.get("last_changed"), tz()),
            "attributes": {
                k: v
                for k, v in attrs.items()
                if k not in DROPPED_ATTRIBUTES and _small(v)
            },
        }
        return {k: v for k, v in out.items() if v not in (None, {})}

    async def time_range(start: str, end: str) -> tuple[datetime, datetime, datetime]:
        now = datetime.now(UTC)
        try:
            begin = history.parse_time(start, now, tz())
            finish = history.parse_time(end, now, tz())
        except history.TimeError as err:
            raise HTTPException(422, str(err)) from err
        if begin >= finish:
            raise HTTPException(422, "start must be before end")
        return begin, min(finish, now), now

    @app.get("/healthz", include_in_schema=False)
    async def healthz() -> dict[str, str]:
        return {"status": "ok"}

    @app.get("/v1/areas", summary="List rooms and how many visible entities each has")
    async def areas(
        caller: Agent,
        include_diagnostic: Annotated[
            bool,
            Query(
                description=(
                    "Also list diagnostic and configuration entities (battery "
                    "voltages, firmware, identify buttons). They are always "
                    "readable directly and through history."
                )
            ),
        ] = False,
    ) -> list[dict[str, Any]]:
        catalog = await ha.catalog()
        out = []
        for area_id, name in sorted(catalog.areas.items(), key=lambda kv: kv[1]):
            visible = [
                e
                for e in catalog.entities_in(area_id)
                if readable(caller, catalog, e)
                and catalog.listed(e, include_diagnostic)
            ]
            domains = sorted({e.split(".", 1)[0] for e in visible})
            out.append(
                {
                    "area_id": area_id,
                    "name": name,
                    "entities": len(visible),
                    "domains": domains,
                }
            )
        return out

    @app.get("/v1/entities", summary="List entities with their current state")
    async def entities(
        caller: Agent,
        area: Annotated[str | None, Query(description="Area name or id")] = None,
        domain: Annotated[
            str | None, Query(description="e.g. light, sensor, climate, cover")
        ] = None,
        q: Annotated[
            str | None, Query(description="Case-insensitive text in the name or id")
        ] = None,
        limit: Annotated[int, Query(ge=1, le=500)] = 200,
        offset: Annotated[int, Query(ge=0)] = 0,
        include_diagnostic: Annotated[
            bool,
            Query(
                description=(
                    "Also list diagnostic and configuration entities (battery "
                    "voltages, firmware, identify buttons). They are always "
                    "readable directly and through history."
                )
            ),
        ] = False,
    ) -> dict[str, Any]:
        catalog = await ha.catalog()
        area_id = None
        if area is not None:
            area_id = catalog.area_id_for(area)
            if area_id is None:
                raise HTTPException(404, f"no area named {area!r}; see /v1/areas")
        rows = []
        for raw in await ha.states():
            entity_id = raw["entity_id"]
            if not readable(caller, catalog, entity_id) or not catalog.listed(
                entity_id, include_diagnostic
            ):
                continue
            if area_id and catalog.entity_area.get(entity_id) != area_id:
                continue
            if domain and not entity_id.startswith(f"{domain}."):
                continue
            item = view(raw, catalog)
            if q and q.casefold() not in f"{entity_id} {item['name']}".casefold():
                continue
            rows.append(item)
        rows.sort(key=lambda r: (r.get("area") or "~", r["entity_id"]))
        return {"total": len(rows), "entities": rows[offset : offset + limit]}

    async def visible_state(caller: Caller, entity_id: str) -> dict[str, Any]:
        catalog = await ha.catalog()
        raw = (
            await ha.state(entity_id) if readable(caller, catalog, entity_id) else None
        )
        if raw is None:  # same answer for excluded and missing: reveal nothing
            raise HTTPException(404, f"no entity {entity_id}")
        return view(raw, catalog)

    @app.get("/v1/entities/{entity_id}", summary="One entity's current state")
    async def entity(
        caller: Agent,
        entity_id: Annotated[str, Path(pattern=r"^[a-z0-9_]+\.[a-z0-9_]+$")],
    ) -> dict[str, Any]:
        return await visible_state(caller, entity_id)

    @app.get(
        "/v1/history",
        summary="An entity's history over a time range",
        description=(
            "Numeric sensors can be summarized into buckets (min/mean/max). Ranges "
            "older than 10 days come from long-term hourly/daily statistics. "
            "Times: 'now', relative like '-12h' or '-7d', or ISO 8601 (local if no "
            "offset)."
        ),
    )
    async def entity_history(
        caller: Agent,
        entity_id: Annotated[str, Query(pattern=r"^[a-z0-9_]+\.[a-z0-9_]+$")],
        start: Annotated[str, Query(description="e.g. '-12h' or '2026-10-08T19:00'")],
        end: Annotated[str, Query()] = "now",
        bucket: Annotated[
            str | None,
            Query(description="Summarize into buckets, e.g. '15m', '1h', '1d'"),
        ] = None,
    ) -> dict[str, Any]:
        item = await visible_state(caller, entity_id)
        begin, finish, now = await time_range(start, end)
        try:
            step = history.parse_bucket(bucket) if bucket else None
        except history.TimeError as err:
            raise HTTPException(422, str(err)) from err
        base = {
            "entity_id": entity_id,
            "name": item["name"],
            "unit": item.get("unit"),
            "start": begin.astimezone(tz()).isoformat(),
            "end": finish.astimezone(tz()).isoformat(),
        }
        if history.needs_statistics(begin, now):
            step = step or history.auto_bucket(begin, finish)
            rows = await ha.statistics(
                entity_id, begin, finish, history.statistics_period(step)
            )
            if not rows:
                raise HTTPException(
                    404,
                    f"no long-term statistics for {entity_id} before the last "
                    f"{history.RAW_HISTORY_DAYS} days",
                )
            return base | history.summarize_statistics(rows, tz())
        rows = await ha.history(entity_id, begin, finish)
        return base | history.summarize(rows, begin, finish, step, tz())

    @app.get("/v1/logbook", summary="Human-readable events (who/what changed when)")
    async def logbook(
        caller: Agent,
        start: Annotated[str, Query(description="e.g. '-24h'")],
        end: Annotated[str, Query()] = "now",
        entity_id: Annotated[
            str | None, Query(pattern=r"^[a-z0-9_]+\.[a-z0-9_]+$")
        ] = None,
        limit: Annotated[int, Query(ge=1, le=500)] = 200,
    ) -> dict[str, Any]:
        catalog = await ha.catalog()
        if entity_id and not readable(caller, catalog, entity_id):
            raise HTTPException(404, f"no entity {entity_id}")
        begin, finish, _ = await time_range(start, end)
        entries = []
        for e in await ha.logbook(begin, finish, entity_id):
            subject = e.get("entity_id")
            if subject and not readable(caller, catalog, subject):
                continue
            entries.append(
                {
                    k: v
                    for k, v in {
                        "when": _local(e.get("when"), tz()),
                        "entity_id": subject,
                        "name": e.get("name"),
                        "message": e.get("message"),
                        "state": e.get("state"),
                    }.items()
                    if v is not None
                }
            )
        return {"total": len(entries), "entries": entries[-limit:]}

    @app.get("/v1/services", summary="Actions this agent may take, and their limits")
    async def services(caller: Agent) -> list[dict[str, Any]]:
        catalog = await ha.catalog()
        present = [s["entity_id"] for s in await ha.states()]
        out = []
        for rule in caller.policy.rules:
            targets = sorted(
                e
                for e in present
                if rule.entities.matches(e) and readable(caller, catalog, e)
            )
            for service in sorted(rule.services):
                domain = service.split(".", 1)[0]
                out.append(
                    {
                        "service": service,
                        "entities": [t for t in targets if t.startswith(f"{domain}.")],
                        "data": {k: c.describe() for k, c in rule.data.items()},
                    }
                )
        return out

    @app.post(
        "/v1/services/{domain}/{service}",
        summary="Call an allowed service",
        description=(
            "Target entities by entity_id and/or area. Every entity is checked "
            "against the policy; out-of-range values are rejected, never adjusted."
        ),
    )
    async def call_service(
        caller: Agent,
        domain: Annotated[str, Path(pattern=r"^[a-z0-9_]+$")],
        service: Annotated[str, Path(pattern=r"^[a-z0-9_]+$")],
        call: ServiceCall,
    ) -> dict[str, Any]:
        name = f"{domain}.{service}"
        requested = _as_list(call.entity_id)
        areas = _as_list(call.area)
        record = {"event": "write", **caller.who(), "service": name}

        async def deny(message: str, status: int = 403) -> HTTPException:
            audit.record(
                **record, decision="denied", reason=message, entities=requested
            )
            await audit.alert(
                "denied", f"{caller.token.name}: denied {name}: {message}"
            )
            return HTTPException(status, message)

        if name not in caller.policy.services():
            raise await deny(f"{name} is not allowed; see /v1/services for what is")
        if not requested and not areas:
            raise HTTPException(422, "give entity_id and/or area")
        catalog = await ha.catalog()
        present = {s["entity_id"] for s in await ha.states()}

        targets: list[str] = []
        for entity_id in requested:
            if entity_id not in present or not readable(caller, catalog, entity_id):
                raise HTTPException(404, f"no entity {entity_id}")
            targets.append(entity_id)
        skipped: list[str] = []
        for area in areas:
            area_id = catalog.area_id_for(area)
            if area_id is None:
                raise HTTPException(404, f"no area named {area!r}; see /v1/areas")
            for entity_id in catalog.entities_in(area_id):
                if (
                    not entity_id.startswith(f"{domain}.")
                    or entity_id not in present
                    or not readable(caller, catalog, entity_id)  # never reveal
                ):
                    continue
                if caller.policy.entity_allowed(name, entity_id):
                    targets.append(entity_id)
                else:
                    skipped.append(entity_id)
        targets = sorted(set(targets))
        if not targets:
            raise await deny(
                f"no entities {name} is allowed to act on"
                + (f" (skipped: {', '.join(skipped)})" if skipped else "")
            )
        try:
            for entity_id in targets:
                caller.policy.check_write(name, entity_id, call.data)
        except Denied as err:
            raise await deny(str(err)) from err
        if not limiter.allow(caller.token.name, caller.token.writes_per_hour):
            raise await deny(
                f"write limit reached ({caller.token.writes_per_hour} per hour)",
                status=429,
            )

        await ha.call_service(domain, service, {**call.data, "entity_id": targets})
        audit.record(**record, decision="allowed", entities=targets, data=call.data)
        await audit.write_event(
            **caller.who(), service=name, entities=targets, data=call.data
        )
        return {"called": name, "entities": targets, "skipped": skipped}

    return app


def _as_list(value: str | list[str] | None) -> list[str]:
    if value is None:
        return []
    return [value] if isinstance(value, str) else list(value)


def _local(stamp: str | None, tz: tzinfo) -> str | None:
    if not stamp:
        return None
    try:
        return datetime.fromisoformat(stamp).astimezone(tz).isoformat()
    except ValueError:
        return stamp


def _small(value: Any) -> bool:
    if isinstance(value, list | dict):
        return len(value) <= MAX_ATTRIBUTE_ITEMS
    if isinstance(value, str):
        return len(value) <= MAX_ATTRIBUTE_CHARS
    return True
