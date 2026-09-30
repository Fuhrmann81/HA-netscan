"""End-to-end-Tests der Integration in einer echten HA-Testinstanz."""

import os
from unittest.mock import patch

import pytest
from homeassistant import config_entries
from homeassistant.core import HomeAssistant
from homeassistant.data_entry_flow import FlowResultType
from homeassistant.setup import async_setup_component
from pytest_homeassistant_custom_component.common import MockConfigEntry

from custom_components.ha_netscan import netscan
from custom_components.ha_netscan.const import CONF_INTERVAL, CONF_SUBNET, DOMAIN

KB = netscan.Knowledge(cache_dir=os.path.expanduser("~/.cache/ha_netscan"))
ADAPTERS = [{"name": "eth0", "enabled": True, "auto": True, "default": True, "index": 1,
             "ipv4": [{"address": "192.168.1.10", "network_prefix": 24}], "ipv6": []}]


def fake_hosts():
    H = netscan.Host
    hs = [
        H("192.168.1.3", True, "34:7E:5C:00:00:01", ports=[1400]),
        H("192.168.1.23", True, "EC:FA:BC:12:34:56", hostname="shellyplus1pm-a8",
          ports=[80], mdns={"_shelly._tcp.local.": [{"name": "shellyplus1pm-a8", "props": {}}]}),
        H("192.168.1.31", True, "D8:1F:12:01:02:03", hostname="ESP_000001", ports=[6668]),
        H("192.168.1.60", True, "34:94:54:01:02:03", hostname="esp-garage", ports=[6053]),
    ]
    for h in hs:
        h.vendor = KB.vendor(h.mac)
    return hs


@pytest.fixture
def patched_scan():
    with patch.object(netscan, "scan_network", side_effect=lambda *a, **k: fake_hosts()), \
         patch("custom_components.ha_netscan.coordinator.NetscanCoordinator._load_kb",
               return_value=KB):
        yield


async def test_config_flow(hass: HomeAssistant) -> None:
    with patch("homeassistant.components.network.async_get_adapters", return_value=ADAPTERS):
        result = await hass.config_entries.flow.async_init(
            DOMAIN, context={"source": config_entries.SOURCE_USER})
    assert result["type"] is FlowResultType.FORM
    schema_defaults = {str(k): k.default() for k in result["data_schema"].schema}
    assert schema_defaults[CONF_SUBNET] == "192.168.1.0/24"

    for bad, err in (("quatsch", "invalid_subnet"), ("10.0.0.0/8", "too_large"),
                     ("8.8.8.0/24", "not_private")):
        r = await hass.config_entries.flow.async_configure(
            result["flow_id"], {CONF_SUBNET: bad, CONF_INTERVAL: 24})
        assert r["errors"] == {CONF_SUBNET: err}, bad

    with patch("custom_components.ha_netscan.async_setup_entry", return_value=True):
        r = await hass.config_entries.flow.async_configure(
            result["flow_id"], {CONF_SUBNET: "192.168.1.7/24", CONF_INTERVAL: 0})
    assert r["type"] is FlowResultType.CREATE_ENTRY
    assert r["options"] == {CONF_SUBNET: "192.168.1.0/24", CONF_INTERVAL: 0}


async def test_setup_scan_sensors_api_panel(hass, hass_client, patched_scan) -> None:
    await async_setup_component(hass, "http", {})
    # Andere Integrationen, die HA schon kennt:
    MockConfigEntry(domain="shelly", title="Licht Keller", data={"host": "192.168.1.23"}).add_to_hass(hass)
    MockConfigEntry(domain="tuya", title="Tuya", data={}).add_to_hass(hass)
    MockConfigEntry(domain="sonos", title="Sonos", data={}).add_to_hass(hass)

    entry = MockConfigEntry(domain=DOMAIN, title="Netzwerk-Inventar",
                            options={CONF_SUBNET: "192.168.1.0/24", CONF_INTERVAL: 0})
    entry.add_to_hass(hass)
    assert await hass.config_entries.async_setup(entry.entry_id)
    await hass.async_block_till_done(wait_background_tasks=True)

    coord = entry.runtime_data
    assert coord.data is not None, coord.last_exception
    s = coord.data["summary"]
    print(s)
    assert s["devices"] == 4
    assert s["done"] == 3          # Sonos, Shelly (per IP), Tuya-Cloud
    assert s["upgrade"] == 1       # Tuya lokal
    assert s["open"] == 1          # ESPHome

    states = {st.entity_id: st for st in hass.states.async_all()}
    print(sorted(states))
    dev = next(st for eid, st in states.items() if eid.startswith("sensor.") and st.attributes.get("unit_of_measurement") and "open" not in eid and st.state == "4")
    assert dev
    open_s = next(st for st in states.values() if st.attributes.get("devices"))
    assert open_s.state == "1" and open_s.attributes["devices"][0]["ip"] == "192.168.1.60"
    html = coord.data["html"]
    assert "eingerichtet als „Licht Keller“" in html
    assert "über Tuya-Cloud eingebunden" in html

    # Panel & API
    assert "netzwerk-inventar" in hass.data["frontend_panels"]
    client = await hass_client()
    r = await client.get("/api/ha_netscan/report")
    assert r.status == 200
    j = await r.json()
    assert j["summary"]["devices"] == 4 and "<table>" in j["html"] and j["scanning"] is False
    r = await client.get("/ha_netscan_static/panel.js")
    assert r.status == 200 and "ha-netscan-panel" in await r.text()
    r = await client.post("/api/ha_netscan/report")
    assert (await r.json())["started"] is True
    await hass.async_block_till_done(wait_background_tasks=True)

    # Button
    btn = next(eid for eid in states if eid.startswith("button."))
    await hass.services.async_call("button", "press", {"entity_id": btn}, blocking=True)
    await hass.async_block_till_done(wait_background_tasks=True)

    # Entladen
    assert await hass.config_entries.async_unload(entry.entry_id)
    assert "netzwerk-inventar" not in hass.data["frontend_panels"]
    # Wieder laden (statische Pfade dürfen nicht doppelt registriert werden)
    assert await hass.config_entries.async_setup(entry.entry_id)
    await hass.async_block_till_done(wait_background_tasks=True)
    assert "netzwerk-inventar" in hass.data["frontend_panels"]
