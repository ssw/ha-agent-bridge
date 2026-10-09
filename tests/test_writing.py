"""What an agent can change, and everything it can't."""

import pytest

from tests.conftest import MUSE, POLICY, READER, bridge


def call(client, service, headers=MUSE, **body):
    domain, name = service.split(".")
    return client.post(f"/v1/services/{domain}/{name}", json=body, headers=headers)


def test_dim_a_light(client, ha):
    resp = call(
        client,
        "light.turn_on",
        entity_id="light.big_general_downlights",
        data={"brightness_pct": 40},
    )
    assert resp.status_code == 200
    assert resp.json() == {
        "called": "light.turn_on",
        "entities": ["light.big_general_downlights"],
        "skipped": [],
    }
    assert ha.service_calls("light.turn_on") == [
        {"brightness_pct": 40, "entity_id": ["light.big_general_downlights"]}
    ]
    # each write is recorded in HA as an event, attributed to the agent
    assert ha.events == [
        (
            "agent_bridge_call",
            {
                "token": "sam-muse",
                "policy": "home-control",
                "service": "light.turn_on",
                "entities": ["light.big_general_downlights"],
                "data": {"brightness_pct": 40},
            },
        )
    ]


def test_set_the_thermostat_within_range(client, ha):
    resp = call(
        client,
        "climate.set_temperature",
        entity_id="climate.big_thermostat",
        data={"temperature": 70},
    )
    assert resp.status_code == 200
    assert ha.service_calls("climate.set_temperature") == [
        {"temperature": 70, "entity_id": ["climate.big_thermostat"]}
    ]


def test_out_of_range_temperature_is_rejected_not_adjusted(client, ha):
    resp = call(
        client,
        "climate.set_temperature",
        entity_id="climate.big_thermostat",
        data={"temperature": 85},
    )
    assert resp.status_code == 403
    assert resp.json()["detail"] == "'temperature' must be between 65 and 78 (got 85)"
    assert ha.service_calls("climate.set_temperature") == []
    # denied writes raise an alert in HA
    (alert,) = ha.service_calls("persistent_notification.create")
    assert "denied climate.set_temperature" in alert["message"]


def test_disallowed_mode_lists_the_allowed_ones(client):
    resp = call(
        client,
        "climate.set_hvac_mode",
        entity_id="climate.big_thermostat",
        data={"hvac_mode": "auto"},
    )
    assert resp.status_code == 403
    assert "one of: cool, heat, heat_cool, off" in resp.json()["detail"]


def test_closing_everything_in_the_garage_never_touches_the_garage_door(client, ha):
    resp = call(client, "cover.close_cover", area="garage")
    assert resp.status_code == 403
    assert resp.json()["detail"] == (
        "no entities cover.close_cover is allowed to act on "
        "(skipped: cover.garage_garage_door)"
    )
    assert ha.service_calls("cover.close_cover") == []


def test_naming_the_garage_door_directly_is_denied(client, ha):
    resp = call(client, "cover.open_cover", entity_id="cover.garage_garage_door")
    assert resp.status_code == 403
    assert resp.json()["detail"] == (
        "cover.open_cover is not allowed on cover.garage_garage_door"
    )
    assert ha.service_calls("cover.open_cover") == []


def test_area_targets_expand_to_allowed_entities(client, ha):
    resp = call(client, "light.turn_off", area="garage")
    assert resp.json()["entities"] == ["light.garage_light"]
    assert ha.service_calls("light.turn_off") == [{"entity_id": ["light.garage_light"]}]


def test_one_disallowed_entity_blocks_the_whole_call(client, ha):
    resp = call(
        client,
        "switch.turn_off",
        entity_id=["switch.baby_humidifier", "switch.dishwasher_power"],
    )
    assert resp.status_code == 403
    assert ha.service_calls("switch.turn_off") == []


def test_unlocking_the_front_door_is_not_a_thing(client, ha):
    resp = call(client, "lock.unlock", entity_id="lock.entryway_front_door_lock")
    assert resp.status_code == 403
    assert "lock.unlock is not allowed" in resp.json()["detail"]
    assert ha.service_calls("lock.unlock") == []


def test_unknown_data_fields_are_rejected(client, ha):
    resp = call(
        client,
        "light.turn_on",
        entity_id="light.big_general_downlights",
        data={"brightness_pct": 50, "rgb_color": [255, 0, 0]},
    )
    assert resp.status_code == 403
    assert "'rgb_color' is not allowed" in resp.json()["detail"]
    assert ha.service_calls("light.turn_on") == []


def test_unknown_entities_are_not_found(client):
    resp = call(client, "light.turn_on", entity_id="light.does_not_exist")
    assert resp.status_code == 404


def test_read_only_profile_cannot_write(client, ha):
    resp = call(
        client,
        "light.turn_on",
        headers=READER,
        entity_id="light.big_general_downlights",
    )
    assert resp.status_code == 403
    assert ha.service_calls("light.turn_on") == []


def test_write_rate_limit(ha):
    ha.reset()
    with bridge(ha, POLICY) as client:  # sam-muse may write 5 times an hour
        codes = [
            call(client, "light.toggle", entity_id="light.garage_light").status_code
            for _ in range(6)
        ]
    assert codes == [200] * 5 + [429]
    assert len(ha.service_calls("light.toggle")) == 5


@pytest.mark.parametrize(
    "body",
    [
        {"entity_id": "light.big_general_downlights", "data": {"entity_id": "lock.x"}},
        {
            "entity_id": "light.big_general_downlights",
            "data": {"brightness_pct": "100"},
        },
        {"entity_id": "light.big_general_downlights", "data": {"brightness_pct": True}},
    ],
)
def test_smuggled_targets_and_wrong_types_are_rejected(client, ha, body):
    resp = client.post("/v1/services/light/turn_on", json=body, headers=MUSE)
    assert resp.status_code == 403
    assert ha.service_calls("light.turn_on") == []
