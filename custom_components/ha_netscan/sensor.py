"""Sensoren: Kennzahlen des letzten Scans."""

from __future__ import annotations

from typing import Any

from homeassistant.components.sensor import SensorDeviceClass, SensorEntity, SensorStateClass
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity_platform import AddConfigEntryEntitiesCallback

from . import NetscanConfigEntry
from .entity import NetscanEntity

COUNTERS = {
    "devices": ("devices", "mdi:lan"),
    "open_suggestions": ("open", "mdi:puzzle-plus-outline"),
    "integrated": ("done", "mdi:check-network-outline"),
    "upgrades": ("upgrade", "mdi:arrow-up-bold-circle-outline"),
}


async def async_setup_entry(
    hass: HomeAssistant,
    entry: NetscanConfigEntry,
    async_add_entities: AddConfigEntryEntitiesCallback,
) -> None:
    coord = entry.runtime_data
    entities: list[SensorEntity] = [
        NetscanCounter(coord, key, field, icon) for key, (field, icon) in COUNTERS.items()
    ]
    entities.append(NetscanLastScan(coord))
    async_add_entities(entities)


class NetscanCounter(NetscanEntity, SensorEntity):
    _attr_state_class = SensorStateClass.MEASUREMENT

    def __init__(self, coordinator, key: str, field: str, icon: str) -> None:
        super().__init__(coordinator, key)
        self._field = field
        self._attr_icon = icon

    @property
    def native_value(self) -> int | None:
        data = self.coordinator.data
        return data["summary"][self._field] if data else None

    @property
    def extra_state_attributes(self) -> dict[str, Any] | None:
        data = self.coordinator.data
        if self._field != "open" or not data:
            return None
        # Liste für Dashboards/Automationen (begrenzt, damit die Datenbank klein bleibt)
        return {"devices": data["summary"]["open_list"][:25]}


class NetscanLastScan(NetscanEntity, SensorEntity):
    _attr_device_class = SensorDeviceClass.TIMESTAMP
    _attr_icon = "mdi:radar"

    def __init__(self, coordinator) -> None:
        super().__init__(coordinator, "last_scan")

    @property
    def native_value(self):
        data = self.coordinator.data
        return data["last_scan"] if data else None

    @property
    def extra_state_attributes(self) -> dict[str, Any]:
        data = self.coordinator.data or {}
        return {
            "subnet": self.coordinator.subnet,
            "scanning": self.coordinator.scanning,
            "duration_s": data.get("duration"),
        }
