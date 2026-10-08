"""Netzwerk-Inventar: scannt das Heimnetz und schlägt passende Integrationen vor."""

from __future__ import annotations

import logging
from pathlib import Path

from aiohttp import web

from homeassistant.components import frontend, panel_custom
from homeassistant.components.http import HomeAssistantView, StaticPathConfig
from homeassistant.config_entries import ConfigEntry
from homeassistant.const import Platform
from homeassistant.core import HomeAssistant
from homeassistant.helpers.start import async_at_started

from .const import VERSION, API_URL, DOMAIN, NAME, PANEL_ELEMENT, PANEL_URL, STATIC_URL
from .coordinator import NetscanCoordinator

_LOGGER = logging.getLogger(__name__)
PLATFORMS = [Platform.SENSOR, Platform.BUTTON]

type NetscanConfigEntry = ConfigEntry[NetscanCoordinator]


async def async_setup_entry(hass: HomeAssistant, entry: NetscanConfigEntry) -> bool:
    coordinator = NetscanCoordinator(hass, entry)
    entry.runtime_data = coordinator
    hass.data.setdefault(DOMAIN, {})["coordinator"] = coordinator

    await _async_register_frontend(hass)
    await hass.config_entries.async_forward_entry_setups(entry, PLATFORMS)
    entry.async_on_unload(entry.add_update_listener(_async_reload))

    # Erster Scan erst, wenn Home Assistant vollständig gestartet ist
    async def _first_scan(_hass: HomeAssistant) -> None:
        coordinator.async_start_scan()

    entry.async_on_unload(async_at_started(hass, _first_scan))
    return True


async def async_unload_entry(hass: HomeAssistant, entry: NetscanConfigEntry) -> bool:
    ok = await hass.config_entries.async_unload_platforms(entry, PLATFORMS)
    if ok:
        frontend.async_remove_panel(hass, PANEL_URL)
        hass.data.get(DOMAIN, {}).pop("coordinator", None)
        hass.data.get(DOMAIN, {}).pop("panel", None)
    return ok


async def _async_reload(hass: HomeAssistant, entry: NetscanConfigEntry) -> None:
    await hass.config_entries.async_reload(entry.entry_id)


async def _async_register_frontend(hass: HomeAssistant) -> None:
    data = hass.data.setdefault(DOMAIN, {})
    if not data.get("static"):
        # Statische Pfade und API lassen sich nicht wieder abmelden – nur einmal pro Start
        await hass.http.async_register_static_paths(
            [StaticPathConfig(STATIC_URL, str(Path(__file__).parent / "frontend"), False)]
        )
        hass.http.register_view(NetscanReportView())
        data["static"] = True
    if not data.get("panel"):
        await panel_custom.async_register_panel(
            hass,
            frontend_url_path=PANEL_URL,
            webcomponent_name=PANEL_ELEMENT,
            sidebar_title=NAME,
            sidebar_icon="mdi:lan-check",
            module_url=f"{STATIC_URL}/panel.js?v={VERSION}",
            require_admin=True,
            config={"version": VERSION},
        )
        data["panel"] = True


class NetscanReportView(HomeAssistantView):
    """Liefert den Bericht an das Seitenleisten-Panel (nur angemeldete Admins)."""

    url = API_URL
    name = "api:ha_netscan:report"
    requires_auth = True

    async def get(self, request: web.Request) -> web.Response:
        hass: HomeAssistant = request.app["hass"]
        if not request["hass_user"].is_admin:
            return self.json_message("Nur für Administratoren", 403)
        coord: NetscanCoordinator | None = hass.data.get(DOMAIN, {}).get("coordinator")
        if coord is None:
            return self.json_message("Integration nicht geladen", 404)
        data = coord.data or {}
        return self.json(
            {
                "scanning": coord.scanning,
                "subnet": coord.subnet,
                "last_scan": data["last_scan"].isoformat() if data.get("last_scan") else None,
                "summary": {k: v for k, v in data.get("summary", {}).items() if k != "open_list"},
                "html": data.get("html"),
                "error": None if coord.last_update_success else str(coord.last_exception),
            }
        )

    async def post(self, request: web.Request) -> web.Response:
        hass: HomeAssistant = request.app["hass"]
        if not request["hass_user"].is_admin:
            return self.json_message("Nur für Administratoren", 403)
        coord: NetscanCoordinator | None = hass.data.get(DOMAIN, {}).get("coordinator")
        if coord is None:
            return self.json_message("Integration nicht geladen", 404)
        return self.json({"started": coord.async_start_scan()})
