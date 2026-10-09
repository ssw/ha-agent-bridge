# Agent Bridge

A Home Assistant add-on that lets AI agents (for example Meta's Muse) read and
control a home through a small, policy-enforced HTTP API, reached through a
Cloudflare Tunnel. Agents never hold a Home Assistant credential, and Home
Assistant itself is never exposed to the internet.

```
agent (cloud) -> Cloudflare -> tunnel (outbound from the add-on)
              -> bridge on the add-on's localhost
                   checks the agent's token, the policy, the kill switch
              -> Home Assistant, with a non-admin user's token
```

## Why a bridge

Home Assistant tokens are all-or-nothing: any token, even a non-admin user's,
can operate every device, locks included. The bridge holds the only HA token
and exposes a generic API whose every read and write is checked against a
policy:

- **Reads** are broad with exclusions (for example, hide people, phone trackers
  and phone sensors). Excluded entities look exactly like missing ones.
- **Writes** are an explicit allowlist of services, entities and value ranges.
  Out-of-range values are rejected, not adjusted. Unknown data fields are
  rejected. Room targets are expanded and each entity is checked, so "close
  everything in the garage" can't reach a garage door the policy excludes.
- **Per-agent tokens** map to separate policy profiles; only SHA-256 hashes are
  stored.
- **Audit**: every request is logged; every write fires an
  `agent_bridge_call` event in HA; denied writes and bad tokens raise an alert.
- **Kill switch**: `enabled = false` globally or per profile blocks reads and
  writes.

## API

```
GET  /openapi.json                       no token needed
GET  /v1/areas
GET  /v1/entities?area=&domain=&q=&include_diagnostic=
GET  /v1/entities/{entity_id}
GET  /v1/history?entity_id=&start=-12h&end=now&bucket=1h
GET  /v1/logbook?start=-24h
GET  /v1/services                        what this agent may do, with limits
POST /v1/services/{domain}/{service}     {"entity_id" | "area", "data"}
```

Listings leave out Home Assistant's diagnostic and configuration entities
(battery voltages, firmware, identify buttons) unless `include_diagnostic=true`;
they stay readable directly and through history.

Times accept `now`, relative offsets like `-12h` / `-7d`, or ISO 8601 (local
time when no offset is given). Ranges older than 10 days are served from HA's
long-term statistics.

## Policy

TOML, set in the add-on's `policy` option. See the docstring at the top of
[`policy.py`](agent_bridge/src/agent_bridge/policy.py) for the format. A minimal
read-only agent:

```toml
[profiles.reader]
token_sha256 = ["<sha256 hex of the agent's token>"]

[profiles.reader.read]
exclude_domains = ["person", "device_tracker"]
exclude_integrations = ["mobile_app"]
```

## Setup

1. Create a non-admin Home Assistant user for the bridge and a long-lived token
   for it. Don't use an admin token.
2. Create a Cloudflare Tunnel with a public hostname that routes to
   `http://localhost:8099`. Restrict the hostname with WAF rules to
   `/openapi.json`, `GET /v1/*` and `POST /v1/services/*`, and rate-limit it.
3. Add this repository to Home Assistant's add-on store, install **Agent
   Bridge**, and set `ha_url`, `ha_token`, `tunnel_token`, `public_url` and
   `policy`.

The add-on is deliberately configured with `homeassistant_api: false` (that
Supervisor token would be admin-level), no ports and no host networking. The
bridge listens only on the container's localhost; the tunnel cannot reach Home
Assistant's own web interface.

## Development

```sh
uv run --python 3.13 pytest          # end-to-end tests against a fake HA
pre-commit install                   # ruff lint + format on commit
```

Dependencies are pinned to releases at least two weeks old (`exclude-newer` in
`pyproject.toml`); `agent_bridge/requirements.lock` is hash-pinned for the
image build.
