"""Tokens, the kill switch, and policy validation."""

import pytest
from agent_bridge.policy import PolicyError, parse

from tests.conftest import MUSE, OFF, POLICY, auth, bridge


def test_missing_or_wrong_token_is_rejected_and_alerted(client, ha):
    assert client.get("/v1/areas").status_code == 401
    assert client.get("/v1/areas", headers=auth("guess")).status_code == 401
    # alerts are throttled: one per kind per window
    (alert,) = ha.service_calls("persistent_notification.create")
    assert "bad token" in alert["message"]


def test_a_disabled_profile_blocks_reads_too(client):
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


RULE = '[profiles.a]\n[[profiles.a.allow]]\nservices = ["{service}"]\n{rest}'


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
        ('[profiles.a]\ntoken_sha256 = ["nothex"]', "sha256"),
        ("[profiles.a]\nwrites = 5", "unknown key"),
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
