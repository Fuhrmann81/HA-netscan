"""Scan-Koordinator für Netzwerk-Inventar."""

from __future__ import annotations

import asyncio
import ipaddress
import logging
import re
import time
from datetime import timedelta
from typing import Any
from urllib.parse import urlparse

from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator, UpdateFailed
from homeassistant.util import dt as dt_util

from . import netscan
from .const import CONF_INTERVAL, CONF_SUBNET, DEFAULT_INTERVAL, DOMAIN, HOST_KEYS

_LOGGER = logging.getLogger(__name__)
KB_MAX_AGE = 7 * 24 * 3600
_IP_RE = re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b")


def _sink(msg: str) -> None:
    msg = msg.strip()
    if msg.startswith("!"):
        _LOGGER.warning(msg.lstrip("! "))
    elif msg:
        _LOGGER.debug(msg)


netscan.LOG_SINK = _sink


class NetscanCoordinator(DataUpdateCoordinator[dict[str, Any]]):
    """Führt Scans aus und hält das letzte Ergebnis."""

    config_entry: ConfigEntry

    def __init__(self, hass: HomeAssistant, entry: ConfigEntry) -> None:
        hours = entry.options.get(CONF_INTERVAL, DEFAULT_INTERVAL)
        super().__init__(
            hass,
            _LOGGER,
            config_entry=entry,
            name=DOMAIN,
            update_interval=timedelta(hours=hours) if hours else None,
        )
        self.subnet: str = entry.options[CONF_SUBNET]
        self.scanning = False
        self._lock = asyncio.Lock()
        self._kb: netscan.Knowledge | None = None
        self._cache_dir = hass.config.path(".storage", "ha_netscan_cache")

    # ------------------------------------------------------------------
    @callback
    def async_start_scan(self) -> bool:
        """Scan im Hintergrund starten. False, wenn schon einer läuft."""
        if self._lock.locked():
            return False
        self.config_entry.async_create_background_task(
            self.hass, self.async_refresh(), f"{DOMAIN}_scan"
        )
        return True

    # ------------------------------------------------------------------
    def _installed(self) -> tuple[set[str], dict[str, list[tuple[str, str]]]]:
        """Eingerichtete Integrationen und – wo bekannt – deren IP-Adressen."""
        comps: set[str] = set()
        for comp in self.hass.config.components:
            comps.update(comp.split("."))
        ip_entries: dict[str, list[tuple[str, str]]] = {}
        net = ipaddress.ip_network(self.subnet, strict=False)
        for entry in self.hass.config_entries.async_entries():
            if entry.disabled_by or entry.domain == DOMAIN:
                continue
            comps.add(entry.domain)
            for source in (entry.data, entry.options):
                for key in HOST_KEYS:
                    value = source.get(key) if hasattr(source, "get") else None
                    if not isinstance(value, str):
                        continue
                    host = urlparse(value).hostname if "://" in value else value
                    m = _IP_RE.search(host or "")
                    if not m:
                        continue
                    try:
                        if ipaddress.ip_address(m.group(1)) not in net:
                            continue
                    except ValueError:
                        continue
                    lst = ip_entries.setdefault(m.group(1), [])
                    if (entry.domain, entry.title) not in lst:
                        lst.append((entry.domain, entry.title))
        return comps, ip_entries

    def _load_kb(self) -> netscan.Knowledge:
        if self._kb is None or time.time() - self._kb.loaded_at > KB_MAX_AGE:
            self._kb = netscan.Knowledge(cache_dir=self._cache_dir)
        return self._kb

    def _run(self, comps: set, ip_entries: dict) -> dict[str, Any]:
        t0 = time.time()
        kb = self._load_kb()
        hosts = netscan.scan_network(self.subnet, kb)
        netscan.evaluate(hosts, kb, comps, ip_entries)
        meta = {
            "time": dt_util.now().strftime("%d.%m.%Y %H:%M"),
            "duration": time.time() - t0,
            "core": len(kb.core),
            "hacs": len(kb.hacs),
            "ha": True,
            "source": "Home-Assistant-Integration",
        }
        return {
            "hosts": hosts,
            "summary": netscan.summary(hosts),
            "html": netscan.render_html(hosts, self.subnet, meta),
            "duration": round(meta["duration"]),
        }

    async def _async_update_data(self) -> dict[str, Any]:
        async with self._lock:
            self.scanning = True
            self.async_update_listeners()
            try:
                comps, ip_entries = self._installed()
                result = await self.hass.async_add_executor_job(self._run, comps, ip_entries)
            except Exception as err:  # noqa: BLE001
                raise UpdateFailed(f"Scan fehlgeschlagen: {err}") from err
            finally:
                self.scanning = False
            result["last_scan"] = dt_util.utcnow()
            _LOGGER.info(
                "Netzwerk-Scan fertig: %s Geräte, %s offene Vorschläge (%s s)",
                result["summary"]["devices"], result["summary"]["open"], result["duration"],
            )
            return result
