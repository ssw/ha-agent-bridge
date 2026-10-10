"""What an agent can learn about the house, and what stays hidden."""

from datetime import timedelta

from tests.conftest import MUSE, bridge


def test_openapi_describes_the_api_without_a_token(client):
    spec = client.get("/openapi.json").json()
    assert spec["servers"] == [{"url": "https://ha-bridge.example.test"}]
    assert "/v1/services/{domain}/{service}" in spec["paths"]
    assert "HTTPBearer" in spec["components"]["securitySchemes"]


def test_areas_list_rooms_with_only_visible_entities(client):
    areas = {a["name"]: a for a in client.get("/v1/areas", headers=MUSE).json()}
    assert set(areas) == {"baby", "big", "garage", "entryway", "sam shed"}
    # entryway holds the lock, a person (excluded) and a hidden keypad LED
    assert areas["entryway"]["entities"] == 1
    assert areas["entryway"]["domains"] == ["lock"]
    # the garage door is placed through its device's area
    assert "cover" in areas["garage"]["domains"]


def test_find_the_baby_room_temperature_sensor(client):
    found = client.get(
        "/v1/entities", params={"area": "baby", "domain": "sensor"}, headers=MUSE
    ).json()
    assert found["total"] == 1
    sensor = found["entities"][0]
    assert sensor == sensor | {
        "entity_id": "sensor.baby_room_sensor_temperature",
        "name": "Temperature",
        "area": "baby",
        "state": "69.5",
        "unit": "°F",
        "device_class": "temperature",
    }
    assert sensor["last_changed"].endswith(("-07:00", "-08:00"))  # local time


def test_people_phones_and_hidden_entities_never_appear(client):
    ids = {
        e["entity_id"]
        for e in client.get("/v1/entities", headers=MUSE).json()["entities"]
    }
    assert "lock.entryway_front_door_lock" in ids  # lock state stays readable
    assert (
        not {
            "person.sam",
            "device_tracker.samwang_iphone",
            "sensor.samwang_iphone_battery_level",
            "switch.keypad_welcome_led",
        }
        & ids
    )
    # Excluded entities look exactly like missing ones.
    for entity_id in ("person.sam", "device_tracker.samwang_iphone"):
        resp = client.get(f"/v1/entities/{entity_id}", headers=MUSE)
        assert resp.status_code == 404
        assert resp.json() == {"detail": f"no entity {entity_id}"}


def test_last_night_in_the_baby_room_in_hourly_buckets(client, now):
    start = now - timedelta(hours=14)
    end = now - timedelta(hours=2)
    body = client.get(
        "/v1/history",
        params={
            "entity_id": "sensor.baby_room_sensor_temperature",
            "start": start.isoformat(),
            "end": end.isoformat(),
            "bucket": "1h",
        },
        headers=MUSE,
    ).json()
    assert body["kind"] == "buckets"
    assert body["unit"] == "°F"
    assert len(body["buckets"]) == 12
    for b in body["buckets"]:
        assert 69 <= b["min"] <= b["mean"] <= b["max"] <= 70.5


def test_relative_times_work(client):
    body = client.get(
        "/v1/history",
        params={"entity_id": "sensor.baby_room_sensor_temperature", "start": "-6h"},
        headers=MUSE,
    ).json()
    assert body["kind"] == "changes"  # few points, no bucket asked for
    assert 12 <= len(body["changes"]) <= 13


def test_on_off_history_is_a_list_of_changes(client):
    body = client.get(
        "/v1/history",
        params={"entity_id": "light.big_general_downlights", "start": "-12h"},
        headers=MUSE,
    ).json()
    assert [c["state"] for c in body["changes"]] == ["off", "on"]


def test_last_month_comes_from_long_term_statistics(client):
    body = client.get(
        "/v1/history",
        params={
            "entity_id": "sensor.baby_room_sensor_temperature",
            "start": "-25d",
            "end": "-15d",
            "bucket": "1d",
        },
        headers=MUSE,
    ).json()
    assert body["kind"] == "statistics"
    assert body["buckets"]
    assert (
        body["buckets"][0] | {"min": 68.0, "mean": 70.0, "max": 72.0}
        == body["buckets"][0]
    )


THREE_WEEKS_AGO = {
    "entity_id": "cover.garage_garage_door",
    "start": "-22d",
    "end": "-20d",
}


def test_on_off_history_beyond_ha_default_retention_is_unavailable(client):
    # HA keeps 10 days by default, and a door has no long-term statistics.
    response = client.get("/v1/history", params=THREE_WEEKS_AGO, headers=MUSE)
    assert response.status_code == 404
    assert "before the last 10 days" in response.json()["detail"]


def test_longer_retention_reaches_older_on_off_history(ha):
    # A house whose recorder keeps 90 days: when was the garage open?
    ha.reset()
    with bridge(ha, history_days=90) as client:
        body = client.get("/v1/history", params=THREE_WEEKS_AGO, headers=MUSE).json()
    assert [c["state"] for c in body["changes"]] == ["closed", "open", "closed"]


def test_numbers_older_than_the_retention_still_come_from_statistics(ha):
    ha.reset()
    with bridge(ha, history_days=90) as client:
        body = client.get(
            "/v1/history",
            params={
                "entity_id": "sensor.baby_room_sensor_temperature",
                "start": "-120d",
                "end": "-100d",
                "bucket": "1d",
            },
            headers=MUSE,
        )
    # The scenario's statistics only cover the last 30 days.
    assert body.status_code == 404
    assert "before the last 90 days" in body.json()["detail"]


def test_history_of_an_excluded_entity_is_not_found(client):
    resp = client.get(
        "/v1/history",
        params={"entity_id": "device_tracker.samwang_iphone", "start": "-6h"},
        headers=MUSE,
    )
    assert resp.status_code == 404


def test_bad_times_explain_the_accepted_formats(client):
    resp = client.get(
        "/v1/history",
        params={"entity_id": "light.big_general_downlights", "start": "last tuesday"},
        headers=MUSE,
    )
    assert resp.status_code == 422
    assert "'-12h'" in resp.json()["detail"]


def test_logbook_hides_entries_about_excluded_entities(client):
    entries = client.get("/v1/logbook", params={"start": "-24h"}, headers=MUSE).json()
    messages = [e["message"] for e in entries["entries"]]
    assert messages == ["was unlocked", "turned on"]  # not "arrived home"


def test_services_show_exactly_what_can_be_done(client):
    services = {
        s["service"]: s for s in client.get("/v1/services", headers=MUSE).json()
    }
    assert services["climate.set_temperature"]["data"]["temperature"] == {
        "min": 65,
        "max": 78,
    }
    assert services["cover.close_cover"]["entities"] == ["cover.baby_south_shade"]
    assert services["switch.turn_on"]["entities"] == ["switch.baby_humidifier"]
    assert not any(s.startswith("lock.") for s in services)


def test_listings_leave_out_diagnostic_and_config_entities(client):
    areas = {a["name"]: a for a in client.get("/v1/areas", headers=MUSE).json()}
    # baby: temperature, shade, humidifier; not the shade's battery or identify
    assert areas["baby"]["entities"] == 3
    assert areas["baby"]["domains"] == ["cover", "sensor", "switch"]
    listed = client.get(
        "/v1/entities", params={"area": "baby", "domain": "sensor"}, headers=MUSE
    ).json()
    assert [e["entity_id"] for e in listed["entities"]] == [
        "sensor.baby_room_sensor_temperature"
    ]


def test_diagnostic_entities_are_available_on_request(client):
    everything = client.get(
        "/v1/entities",
        params={"area": "baby", "include_diagnostic": "true"},
        headers=MUSE,
    ).json()
    ids = {e["entity_id"] for e in everything["entities"]}
    assert {
        "sensor.baby_south_shade_battery",
        "button.baby_south_shade_identify",
    } <= ids
    areas = client.get(
        "/v1/areas", params={"include_diagnostic": "true"}, headers=MUSE
    ).json()
    assert next(a for a in areas if a["name"] == "baby")["entities"] == 5
    # and always readable directly, e.g. "how are the shade batteries?"
    battery = client.get(
        "/v1/entities/sensor.baby_south_shade_battery", headers=MUSE
    ).json()
    assert battery["state"] == "92"
