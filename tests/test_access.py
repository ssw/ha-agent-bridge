"""Tokens, the kill switch, and policy validation."""

import json

import pytest
from agent_bridge.policy import PolicyError, parse

from tests.conftest import MUSE, OFF, POLICY, READER, TABLET, auth, bridge


def test_missing_or_wrong_token_is_rejected_and_alerted(client, ha):
    assert client.get("/v1/areas").status_code == 401
    assert client.get("/v1/areas", headers=auth("guess")).status_code == 401
    # alerts are throttled: one per kind per window
    (alert,) = ha.service_calls("persistent_notification.create")
    assert "bad token" in alert["message"]


def test_a_disabled_token_blocks_reads_too(client):
    resp = client.get("/v1/entities", headers=OFF)
    assert resp.status_code == 403
    assert resp.json() == {"detail": "agent access is disabled"}


def test_the_global_kill_switch_blocks_everything(ha):
    with bridge(ha, POLICY.replace("enabled = true", "enabled = false", 1)) as client:
        assert client.get("/v1/areas", headers=MUSE).status_code == 403
        resp = client.post(
            "/v1/services/light/turn_on",
            json={"entity_id": "light.garage_light"},
            headers=MUSE,
        )
        assert resp.status_code == 403


RULE = '[policies.a]\n[[policies.a.allow]]\nservices = ["{service}"]\n{rest}'
TOKEN = "[policies.p]\n[tokens.t]\n{body}"
HEX = "0" * 64
TWO_TOKENS = (
    "[policies.p]\n"
    f'[tokens.a]\nsha256 = "{HEX}"\npolicy = "p"\n'
    f'[tokens.b]\nsha256 = "{HEX}"\npolicy = "p"'
)


@pytest.mark.parametrize(
    ("policy", "message"),
    [
        (
            RULE.format(
                service="homeassistant.restart",
                rest='entities = { domains = ["light"] }',
            ),
            "system service",
        ),
        (
            RULE.format(service="light.turn_on", rest="entities = {}"),
            "must name domains or ids",
        ),
        (
            RULE.format(
                service="light.turn_on",
                rest='entities = { domains = ["light"] }\ndata = { entity_id = "any" }',
            ),
            "targets can't be data fields",
        ),
        (TOKEN.format(body='sha256 = "nothex"\npolicy = "p"'), "sha256"),
        (
            TOKEN.format(body=f'sha256 = "{HEX}"\npolicy = "p"\nwrites = 5'),
            "unknown key",
        ),
        (
            TOKEN.format(body=f'sha256 = "{HEX}"\npolicy = "nope"'),
            "no policy 'nope' \\(have: p\\)",
        ),
        (
            TWO_TOKENS,
            "same sha256",
        ),
        ("[policies.Home]", "lowercase letters"),
        ("[profiles.muse]\ntoken_sha256 = []", "unknown key"),  # the old format
        (
            RULE.format(
                service="light.turn_on",
                rest='entities = { domains = ["light"] }\n'
                "data = { brightness_pct = [100, 0] }",
            ),
            "[min, max]",
        ),
    ],
)
def test_invalid_policies_are_refused_with_a_reason(policy, message):
    with pytest.raises(
        PolicyError, match=message.replace("[", r"\[").replace("]", r"\]")
    ):
        parse(policy)


def test_tokens_sharing_a_policy_are_told_apart(client, ha):
    for headers in (MUSE, TABLET):
        client.post(
            "/v1/services/light/turn_on",
            json={"entity_id": "light.garage_light"},
            headers=headers,
        )
    assert [(e["token"], e["policy"]) for _, e in ha.events] == [
        ("sam-muse", "home-control"),
        ("kitchen-tablet", "home-control"),
    ]


def test_denial_alerts_name_the_token(client, ha):
    client.post(
        "/v1/services/lock/unlock",
        json={"entity_id": "lock.entryway_front_door_lock"},
        headers=TABLET,
    )
    (alert,) = ha.service_calls("persistent_notification.create")
    assert alert["message"].startswith("kitchen-tablet: denied lock.unlock")


def test_write_limits_are_per_token(ha):
    ha.reset()
    with bridge(ha) as client:

        def toggle(headers):
            return client.post(
                "/v1/services/light/toggle",
                json={"entity_id": "light.garage_light"},
                headers=headers,
            ).status_code

        assert [toggle(MUSE) for _ in range(6)] == [200] * 5 + [429]
        assert toggle(TABLET) == 200  # its own allowance


def test_disabling_a_policy_blocks_every_token_using_it(ha):
    off = POLICY.replace(
        "[policies.home-control.read]",
        "[policies.home-control]\nenabled = false\n\n[policies.home-control.read]",
    )
    with bridge(ha, off) as client:
        assert client.get("/v1/areas", headers=MUSE).status_code == 403
        assert client.get("/v1/areas", headers=TABLET).status_code == 403
        assert client.get("/v1/areas", headers=READER).status_code == 200


CLOUDFLARE = {
    "CF-Connecting-IP": "203.0.113.7",
    "CF-IPCountry": "US",
    "User-Agent": "Python-urllib/3.13",
}


def test_bad_token_alerts_say_where_the_request_came_from(client, ha):
    client.get("/v1/areas", headers=CLOUDFLARE | auth("guess"))
    (alert,) = ha.service_calls("persistent_notification.create")
    assert alert["message"] == (
        "Rejected a request with a bad token: /v1/areas from 203.0.113.7 (US), "
        "user agent 'Python-urllib/3.13'"
    )


def test_every_request_is_audited_with_token_and_client(client, caplog):
    caplog.set_level("INFO", logger="agent_bridge.audit")
    client.get("/v1/areas", headers=CLOUDFLARE | MUSE)
    client.get("/v1/areas", headers=CLOUDFLARE)
    lines = [json.loads(r.getMessage()) for r in caplog.records]
    requests = [r for r in lines if r["event"] == "request"]
    assert requests == [
        {
            "event": "request",
            "method": "GET",
            "path": "/v1/areas",
            "query": None,
            "status": 200,
            "ms": requests[0]["ms"],
            "token": "sam-muse",
            "ip": "203.0.113.7",
            "country": "US",
            "ua": "Python-urllib/3.13",
        },
        {
            "event": "request",
            "method": "GET",
            "path": "/v1/areas",
            "query": None,
            "status": 401,
            "ms": requests[1]["ms"],
            "token": None,
            "ip": "203.0.113.7",
            "country": "US",
            "ua": "Python-urllib/3.13",
        },
    ]
    # tokens never appear in the audit log
    assert not any("muse-token" in r.getMessage() for r in caplog.records)


def test_denied_write_alerts_include_the_client(client, ha):
    client.post(
        "/v1/services/lock/unlock",
        json={"entity_id": "lock.entryway_front_door_lock"},
        headers=CLOUDFLARE | MUSE,
    )
    (alert,) = ha.service_calls("persistent_notification.create")
    assert alert["message"].endswith(
        "(from 203.0.113.7 (US), user agent 'Python-urllib/3.13')"
    )
