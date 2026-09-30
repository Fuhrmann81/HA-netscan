"""Config Flow für Netzwerk-Inventar."""

from __future__ import annotations

import ipaddress
from typing import Any

import voluptuous as vol

from homeassistant.components import network
from homeassistant.config_entries import (
    ConfigEntry,
    ConfigFlow,
    ConfigFlowResult,
    OptionsFlow,
)
from homeassistant.core import HomeAssistant, callback

from .const import CONF_INTERVAL, CONF_SUBNET, DEFAULT_INTERVAL, DOMAIN, MIN_PREFIX, NAME


async def async_default_subnet(hass: HomeAssistant) -> str:
    """Subnetz des Netzwerkadapters, den Home Assistant benutzt."""
    try:
        for adapter in await network.async_get_adapters(hass):
            if not adapter["enabled"]:
                continue
            for ip in adapter["ipv4"]:
                net = ipaddress.ip_network(
                    f"{ip['address']}/{ip['network_prefix']}", strict=False
                )
                if not net.is_loopback:
                    return str(net)
    except Exception:  # noqa: BLE001
        pass
    return "192.168.178.0/24"


def _validate(user_input: dict[str, Any]) -> dict[str, str]:
    errors: dict[str, str] = {}
    try:
        net = ipaddress.ip_network(user_input[CONF_SUBNET].strip(), strict=False)
        if net.version != 4 or not net.is_private:
            errors[CONF_SUBNET] = "not_private"
        elif net.prefixlen < MIN_PREFIX:
            errors[CONF_SUBNET] = "too_large"
        else:
            user_input[CONF_SUBNET] = str(net)
    except ValueError:
        errors[CONF_SUBNET] = "invalid_subnet"
    return errors


def _schema(subnet: str, interval: int) -> vol.Schema:
    return vol.Schema(
        {
            vol.Required(CONF_SUBNET, default=subnet): str,
            vol.Required(CONF_INTERVAL, default=interval): vol.All(
                vol.Coerce(int), vol.Range(min=0, max=168)
            ),
        }
    )


class NetscanConfigFlow(ConfigFlow, domain=DOMAIN):
    """Einrichtung über die Oberfläche."""

    VERSION = 1

    async def async_step_user(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        errors: dict[str, str] = {}
        if user_input is not None:
            errors = _validate(user_input)
            if not errors:
                return self.async_create_entry(title=NAME, data={}, options=user_input)
        subnet = (user_input or {}).get(CONF_SUBNET) or await async_default_subnet(self.hass)
        return self.async_show_form(
            step_id="user",
            data_schema=_schema(subnet, DEFAULT_INTERVAL),
            errors=errors,
        )

    @staticmethod
    @callback
    def async_get_options_flow(config_entry: ConfigEntry) -> OptionsFlow:
        return NetscanOptionsFlow()


class NetscanOptionsFlow(OptionsFlow):
    """Subnetz und Intervall nachträglich ändern."""

    async def async_step_init(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        errors: dict[str, str] = {}
        if user_input is not None:
            errors = _validate(user_input)
            if not errors:
                return self.async_create_entry(data=user_input)
        opts = self.config_entry.options
        return self.async_show_form(
            step_id="init",
            data_schema=_schema(
                opts.get(CONF_SUBNET, "192.168.178.0/24"),
                opts.get(CONF_INTERVAL, DEFAULT_INTERVAL),
            ),
            errors=errors,
        )
