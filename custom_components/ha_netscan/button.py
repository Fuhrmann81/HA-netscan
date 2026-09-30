"""Knopf „Jetzt scannen“."""

from __future__ import annotations

from homeassistant.components.button import ButtonEntity
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity_platform import AddConfigEntryEntitiesCallback

from . import NetscanConfigEntry
from .entity import NetscanEntity


async def async_setup_entry(
    hass: HomeAssistant,
    entry: NetscanConfigEntry,
    async_add_entities: AddConfigEntryEntitiesCallback,
) -> None:
    async_add_entities([NetscanScanButton(entry.runtime_data)])


class NetscanScanButton(NetscanEntity, ButtonEntity):
    _attr_icon = "mdi:magnify-scan"

    def __init__(self, coordinator) -> None:
        super().__init__(coordinator, "scan")

    async def async_press(self) -> None:
        self.coordinator.async_start_scan()
