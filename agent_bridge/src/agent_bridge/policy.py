"""The access policy: which agents may read and change what.

The policy is TOML. Reads are broad with exclusions; writes are an explicit
allowlist of services, entities and data constraints. Anything not allowed is
denied.

    enabled = true                    # global kill switch (blocks reads too)

    [profiles.muse]
    token_sha256 = ["<hex>"]          # hashes of this agent's bearer tokens
    enabled = true
    writes_per_hour = 60

    [profiles.muse.read]
    exclude_domains = ["person", "device_tracker"]
    exclude_integrations = ["mobile_app"]
    exclude_entities = []

    [[profiles.muse.allow]]
    services = ["light.turn_on", "light.turn_off"]
    entities = { domains = ["light"], ids = [], exclude = [] }
    data = { brightness_pct = [0, 100], hvac_mode = ["off", "heat"], x = "any" }
"""

from __future__ import annotations

import hashlib
import hmac
import re
import tomllib
from dataclasses import dataclass, field
from typing import Any

# System-level domains no policy may grant, whatever the file says.
FORBIDDEN_DOMAINS = frozenset(
    {
        "homeassistant",
        "hassio",
        "backup",
        "recorder",
        "logger",
        "system_log",
        "shell_command",
        "python_script",
        "pyscript",
        "rest_command",
    }
)

_SERVICE_RE = re.compile(r"^[a-z0-9_]+\.[a-z0-9_]+$")
_ENTITY_RE = re.compile(r"^[a-z0-9_]+\.[a-z0-9_]+$")
_HEX64_RE = re.compile(r"^[0-9a-f]{64}$")


class PolicyError(ValueError):
    """The policy file is invalid."""


class Denied(Exception):
    """A request the policy does not allow. The message is shown to the agent."""


def token_hash(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


@dataclass(frozen=True)
class Constraint:
    kind: str  # "range" | "choice" | "any"
    low: float = 0
    high: float = 0
    choices: frozenset[str] = frozenset()

    def check(self, key: str, value: Any) -> None:
        if self.kind == "any":
            if isinstance(value, dict | list):
                raise Denied(f"'{key}' must be a single value")
            return
        if self.kind == "choice":
            if value not in self.choices:
                allowed = ", ".join(sorted(self.choices))
                raise Denied(f"'{key}' must be one of: {allowed} (got {value!r})")
            return
        if isinstance(value, bool) or not isinstance(value, int | float):
            raise Denied(f"'{key}' must be a number (got {value!r})")
        if not self.low <= value <= self.high:
            raise Denied(
                f"'{key}' must be between {_num(self.low)} and {_num(self.high)}"
                f" (got {_num(value)})"
            )

    def describe(self) -> dict[str, Any]:
        if self.kind == "range":
            return {"min": _num(self.low), "max": _num(self.high)}
        if self.kind == "choice":
            return {"one_of": sorted(self.choices)}
        return {"any": True}


def _num(x: float) -> float | int:
    return int(x) if float(x).is_integer() else x


@dataclass(frozen=True)
class EntitySelector:
    domains: frozenset[str] = frozenset()
    ids: frozenset[str] = frozenset()
    exclude: frozenset[str] = frozenset()

    def matches(self, entity_id: str) -> bool:
        if entity_id in self.exclude:
            return False
        return entity_id in self.ids or entity_id.split(".", 1)[0] in self.domains


@dataclass(frozen=True)
class Rule:
    services: frozenset[str]
    entities: EntitySelector
    data: dict[str, Constraint]

    def accepts_data(self, data: dict[str, Any]) -> None:
        for key, value in data.items():
            constraint = self.data.get(key)
            if constraint is None:
                allowed = ", ".join(sorted(self.data)) or "none"
                raise Denied(f"data field '{key}' is not allowed (allowed: {allowed})")
            constraint.check(key, value)


@dataclass(frozen=True)
class ReadPolicy:
    exclude_domains: frozenset[str] = frozenset()
    exclude_integrations: frozenset[str] = frozenset()
    exclude_entities: frozenset[str] = frozenset()

    def allows(self, entity_id: str, integration: str | None) -> bool:
        return not (
            entity_id in self.exclude_entities
            or entity_id.split(".", 1)[0] in self.exclude_domains
            or (integration is not None and integration in self.exclude_integrations)
        )


@dataclass(frozen=True)
class Profile:
    name: str
    token_hashes: frozenset[str]
    enabled: bool = True
    writes_per_hour: int = 60
    read: ReadPolicy = field(default_factory=ReadPolicy)
    rules: tuple[Rule, ...] = ()

    def services(self) -> list[str]:
        return sorted({s for rule in self.rules for s in rule.services})

    def entity_allowed(self, service: str, entity_id: str) -> bool:
        return any(
            service in rule.services and rule.entities.matches(entity_id)
            for rule in self.rules
        )

    def check_write(self, service: str, entity_id: str, data: dict[str, Any]) -> None:
        """Raise Denied unless some rule allows this service, entity and data."""
        rules = [
            r
            for r in self.rules
            if service in r.services and r.entities.matches(entity_id)
        ]
        if not rules:
            raise Denied(f"{service} is not allowed on {entity_id}")
        problems = []
        for rule in rules:
            try:
                rule.accepts_data(data)
                return
            except Denied as err:
                problems.append(str(err))
        raise Denied(problems[0])


@dataclass(frozen=True)
class Policy:
    enabled: bool
    profiles: dict[str, Profile]

    def profile_for_token(self, token: str) -> Profile | None:
        digest = token_hash(token)
        found = None
        for profile in self.profiles.values():
            for known in profile.token_hashes:
                # Check every hash so timing doesn't reveal which matched.
                if hmac.compare_digest(digest, known):
                    found = profile
        return found


def parse(text: str) -> Policy:
    try:
        raw = tomllib.loads(text)
    except tomllib.TOMLDecodeError as err:
        raise PolicyError(f"invalid TOML: {err}") from err
    _only_keys(raw, {"enabled", "profiles"}, "policy")
    profiles = {
        name: _profile(name, spec)
        for name, spec in _table(raw.get("profiles", {}), "profiles").items()
    }
    hashes = [h for p in profiles.values() for h in p.token_hashes]
    if len(hashes) != len(set(hashes)):
        raise PolicyError("the same token hash appears in more than one profile")
    return Policy(enabled=_bool(raw.get("enabled", True), "enabled"), profiles=profiles)


def _profile(name: str, spec: Any) -> Profile:
    where = f"profiles.{name}"
    spec = _table(spec, where)
    _only_keys(
        spec, {"token_sha256", "enabled", "writes_per_hour", "read", "allow"}, where
    )
    hashes = _strings(spec.get("token_sha256", []), f"{where}.token_sha256")
    for h in hashes:
        if not _HEX64_RE.match(h):
            raise PolicyError(
                f"{where}.token_sha256: not a lowercase sha256 hex digest"
            )
    writes = spec.get("writes_per_hour", 60)
    if isinstance(writes, bool) or not isinstance(writes, int) or writes < 0:
        raise PolicyError(f"{where}.writes_per_hour must be a non-negative integer")
    read = _table(spec.get("read", {}), f"{where}.read")
    _only_keys(
        read,
        {"exclude_domains", "exclude_integrations", "exclude_entities"},
        f"{where}.read",
    )
    rules = spec.get("allow", [])
    if not isinstance(rules, list):
        raise PolicyError(f"{where}.allow must be an array of tables ([[...allow]])")
    return Profile(
        name=name,
        token_hashes=frozenset(hashes),
        enabled=_bool(spec.get("enabled", True), f"{where}.enabled"),
        writes_per_hour=writes,
        read=ReadPolicy(
            exclude_domains=frozenset(
                _strings(
                    read.get("exclude_domains", []), f"{where}.read.exclude_domains"
                )
            ),
            exclude_integrations=frozenset(
                _strings(
                    read.get("exclude_integrations", []),
                    f"{where}.read.exclude_integrations",
                )
            ),
            exclude_entities=frozenset(
                _entity_ids(
                    read.get("exclude_entities", []), f"{where}.read.exclude_entities"
                )
            ),
        ),
        rules=tuple(_rule(r, f"{where}.allow[{i}]") for i, r in enumerate(rules)),
    )


def _rule(spec: Any, where: str) -> Rule:
    spec = _table(spec, where)
    _only_keys(spec, {"services", "entities", "data"}, where)
    services = _strings(spec.get("services", []), f"{where}.services")
    if not services:
        raise PolicyError(f"{where}.services must list at least one service")
    for service in services:
        if not _SERVICE_RE.match(service):
            raise PolicyError(f"{where}: '{service}' is not a domain.service name")
        if service.split(".", 1)[0] in FORBIDDEN_DOMAINS:
            raise PolicyError(
                f"{where}: '{service}' is a system service and can't be allowed"
            )
    ents = _table(spec.get("entities", {}), f"{where}.entities")
    _only_keys(ents, {"domains", "ids", "exclude"}, f"{where}.entities")
    selector = EntitySelector(
        domains=frozenset(
            _strings(ents.get("domains", []), f"{where}.entities.domains")
        ),
        ids=frozenset(_entity_ids(ents.get("ids", []), f"{where}.entities.ids")),
        exclude=frozenset(
            _entity_ids(ents.get("exclude", []), f"{where}.entities.exclude")
        ),
    )
    if not selector.domains and not selector.ids:
        raise PolicyError(f"{where}.entities must name domains or ids")
    data = {
        key: _constraint(value, f"{where}.data.{key}")
        for key, value in _table(spec.get("data", {}), f"{where}.data").items()
    }
    if "entity_id" in data or "area_id" in data or "device_id" in data:
        raise PolicyError(f"{where}.data: targets can't be data fields")
    return Rule(services=frozenset(services), entities=selector, data=data)


def _constraint(value: Any, where: str) -> Constraint:
    if value == "any":
        return Constraint("any")
    if isinstance(value, list) and value and all(isinstance(v, str) for v in value):
        return Constraint("choice", choices=frozenset(value))
    if (
        isinstance(value, list)
        and len(value) == 2
        and all(isinstance(v, int | float) and not isinstance(v, bool) for v in value)
        and value[0] <= value[1]
    ):
        return Constraint("range", low=value[0], high=value[1])
    raise PolicyError(f'{where}: use [min, max], a list of allowed strings, or "any"')


def _table(value: Any, where: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise PolicyError(f"{where} must be a table")
    return value


def _only_keys(table: dict[str, Any], allowed: set[str], where: str) -> None:
    unknown = set(table) - allowed
    if unknown:
        raise PolicyError(f"{where}: unknown key(s) {', '.join(sorted(unknown))}")


def _bool(value: Any, where: str) -> bool:
    if not isinstance(value, bool):
        raise PolicyError(f"{where} must be true or false")
    return value


def _strings(value: Any, where: str) -> list[str]:
    if not isinstance(value, list) or not all(isinstance(v, str) for v in value):
        raise PolicyError(f"{where} must be a list of strings")
    return value


def _entity_ids(value: Any, where: str) -> list[str]:
    ids = _strings(value, where)
    for entity_id in ids:
        if not _ENTITY_RE.match(entity_id):
            raise PolicyError(f"{where}: '{entity_id}' is not an entity id")
    return ids
