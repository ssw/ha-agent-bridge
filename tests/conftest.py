"""The scenario house, the policy under test, and clients for each agent."""

from __future__ import annotations

from collections.abc import Iterator
from datetime import UTC, datetime, timedelta

import pytest
from agent_bridge.app import create_app
from agent_bridge.config import Settings
from agent_bridge.policy import token_hash
from fastapi.testclient import TestClient

from tests.fake_ha import HA_TOKEN, Entity, FakeHA, House

MUSE_TOKEN = "muse-token-0123456789abcdef"
READER_TOKEN = "reader-token-0123456789abcdef"
OFF_TOKEN = "off-token-0123456789abcdef"

POLICY = f"""
enabled = true

[profiles.muse]
token_sha256 = ["{token_hash(MUSE_TOKEN)}"]
writes_per_hour = 5

[profiles.muse.read]
exclude_domains = ["person", "device_tracker"]
exclude_integrations = ["mobile_app"]

[[profiles.muse.allow]]
services = ["light.turn_on", "light.turn_off", "light.toggle"]
entities = {{ domains = ["light"] }}
data = {{ brightness_pct = [0, 100], transition = [0, 10] }}

[[profiles.muse.allow]]
services = ["cover.open_cover", "cover.close_cover", "cover.set_cover_position"]
entities = {{ domains = ["cover"], exclude = ["cover.garage_garage_door"] }}
data = {{ position = [0, 100] }}

[[profiles.muse.allow]]
services = ["climate.set_temperature", "climate.set_hvac_mode", "climate.set_fan_mode"]
entities = {{ domains = ["climate"] }}
data = {{ temperature = [65, 78], hvac_mode = ["off", "heat", "cool", "heat_cool"], fan_mode = "any" }}

[[profiles.muse.allow]]
services = ["switch.turn_on", "switch.turn_off"]
entities = {{ ids = ["switch.baby_humidifier"] }}

[profiles.reader]
token_sha256 = ["{token_hash(READER_TOKEN)}"]

[profiles.off]
token_sha256 = ["{token_hash(OFF_TOKEN)}"]
enabled = false
"""


def scenario(now: datetime) -> House:
    temp = "sensor.baby_room_sensor_temperature"
    # Every 30 minutes over the last day: 69.0, 69.5, 70.0, 70.5, 69.0, ...
    history = {
        temp: [
            (
                now - timedelta(hours=24) + timedelta(minutes=30 * i),
                f"{69 + (i % 4) * 0.5}",
            )
            for i in range(48)
        ],
        "light.big_general_downlights": [
            (now - timedelta(hours=10), "off"),
            (now - timedelta(hours=3), "on"),
        ],
    }
    hour = timedelta(hours=1)
    stats_start = now - timedelta(days=30)
    statistics = {
        temp: [
            {
                "start": int((stats_start + hour * i).timestamp() * 1000),
                "mean": 70.0,
                "min": 68.0,
                "max": 72.0,
            }
            for i in range(24 * 20)
        ]
    }
    return House(
        now=now,
        areas={
            "nursery": "baby",
            "big": "big",
            "garage": "garage",
            "entryway": "entryway",
            "shed": "sam shed",
        },
        device_areas={"dev-baby-sensor": "nursery", "dev-garage": "garage"},
        entities=[
            Entity(
                temp,
                "69.5",
                "homekit_controller",
                device_id="dev-baby-sensor",
                attributes={
                    "friendly_name": "Temperature",
                    "unit_of_measurement": "°F",
                    "device_class": "temperature",
                    "state_class": "measurement",
                },
            ),
            Entity(
                "light.big_general_downlights",
                "on",
                "lutron_caseta",
                "big",
                {"friendly_name": "General Downlights", "brightness": 200},
            ),
            Entity(
                "light.garage_light",
                "off",
                "lutron_caseta",
                "garage",
                {"friendly_name": "Garage Light"},
            ),
            Entity(
                "cover.baby_south_shade",
                "open",
                "matter",
                "nursery",
                {"friendly_name": "South Shade", "current_position": 100},
            ),
            Entity(
                "cover.garage_garage_door",
                "closed",
                "homekit_controller",
                device_id="dev-garage",
                attributes={"friendly_name": "Garage Door", "device_class": "garage"},
            ),
            Entity(
                "lock.entryway_front_door_lock",
                "locked",
                "matter",
                "entryway",
                {"friendly_name": "Front Door Lock"},
            ),
            Entity(
                "climate.big_thermostat",
                "heat",
                "homekit_controller",
                "big",
                {
                    "friendly_name": "Thermostat",
                    "temperature": 68,
                    "current_temperature": 69.5,
                    "hvac_modes": ["off", "heat", "cool"],
                },
            ),
            Entity(
                "switch.baby_humidifier",
                "on",
                "matter",
                "nursery",
                {"friendly_name": "Humidifier"},
            ),
            Entity(
                "switch.dishwasher_power",
                "on",
                "miele",
                None,
                {"friendly_name": "Dishwasher Power"},
            ),
            Entity(
                "switch.keypad_welcome_led",
                "off",
                "lutron_caseta",
                "entryway",
                {"friendly_name": "Welcome LED"},
                hidden=True,
            ),
            Entity(
                "person.sam", "home", "person", "entryway", {"friendly_name": "Sam"}
            ),
            Entity(
                "device_tracker.samwang_iphone",
                "home",
                "mobile_app",
                None,
                {"friendly_name": "iPhone", "latitude": 37.7, "longitude": -122.4},
            ),
            Entity(
                "sensor.samwang_iphone_battery_level",
                "81",
                "mobile_app",
                None,
                {"friendly_name": "iPhone Battery"},
            ),
        ],
        history=history,
        statistics=statistics,
        logbook=[
            {
                "when": (now - timedelta(hours=2)).isoformat(),
                "name": "Front Door Lock",
                "message": "was unlocked",
                "entity_id": "lock.entryway_front_door_lock",
            },
            {
                "when": (now - timedelta(hours=1)).isoformat(),
                "name": "Sam",
                "message": "arrived home",
                "entity_id": "person.sam",
            },
            {
                "when": (now - timedelta(minutes=30)).isoformat(),
                "name": "General Downlights",
                "message": "turned on",
                "entity_id": "light.big_general_downlights",
            },
        ],
    )


@pytest.fixture(scope="session")
def now() -> datetime:
    return datetime.now(UTC).replace(microsecond=0)


@pytest.fixture(scope="session")
def ha(now: datetime) -> Iterator[FakeHA]:
    fake = FakeHA(scenario(now))
    fake.start()
    yield fake
    fake.stop()


def bridge(ha: FakeHA, policy: str = POLICY) -> TestClient:
    settings = Settings(
        ha_url=ha.url,
        ha_token=HA_TOKEN,
        policy=policy,
        public_url="https://ha-bridge.example.test",
    )
    return TestClient(create_app(settings))


@pytest.fixture
def client(ha: FakeHA) -> Iterator[TestClient]:
    ha.reset()
    with bridge(ha) as c:
        yield c


def auth(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


MUSE = auth(MUSE_TOKEN)
READER = auth(READER_TOKEN)
OFF = auth(OFF_TOKEN)
