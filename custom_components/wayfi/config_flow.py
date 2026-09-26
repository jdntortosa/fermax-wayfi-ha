"""Config flow for the Fermax Way-Fi integration."""

from __future__ import annotations

import logging
from typing import Any

import voluptuous as vol
from homeassistant.config_entries import ConfigFlow, ConfigFlowResult
from homeassistant.const import CONF_HOST
from homeassistant.helpers.selector import (
    NumberSelector,
    NumberSelectorConfig,
    NumberSelectorMode,
    TextSelector,
    TextSelectorConfig,
    TextSelectorType,
)

from .const import CONF_DEVICE_PASSWORD, CONF_NUM_DOORS, DEFAULT_NUM_DOORS, DEFAULT_PORT, DOMAIN
from .protocol import WayfiConnectionError, test_connection

_LOGGER = logging.getLogger(__name__)

STEP_USER_DATA_SCHEMA = vol.Schema(
    {
        vol.Required(CONF_HOST): TextSelector(TextSelectorConfig(type=TextSelectorType.TEXT)),
        vol.Required(CONF_DEVICE_PASSWORD): TextSelector(
            TextSelectorConfig(type=TextSelectorType.PASSWORD)
        ),
        vol.Required(CONF_NUM_DOORS, default=DEFAULT_NUM_DOORS): NumberSelector(
            NumberSelectorConfig(min=1, max=2, step=1, mode=NumberSelectorMode.BOX)
        ),
    }
)


class WayfiConfigFlow(ConfigFlow, domain=DOMAIN):
    """Handle a config flow for Fermax Way-Fi."""

    VERSION = 1

    async def async_step_user(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Handle the initial (and only) step: host, device password, door count."""
        errors: dict[str, str] = {}

        if user_input is not None:
            host = user_input[CONF_HOST]
            device_password = user_input[CONF_DEVICE_PASSWORD]
            num_doors = int(user_input[CONF_NUM_DOORS])

            await self.async_set_unique_id(host)
            self._abort_if_unique_id_configured()

            try:
                await self.hass.async_add_executor_job(
                    test_connection, host, DEFAULT_PORT, device_password
                )
            except WayfiConnectionError as exc:
                _LOGGER.debug("Connection test failed for %s: %s", host, exc)
                errors["base"] = "cannot_connect"
            else:
                return self.async_create_entry(
                    title=f"Fermax Way-Fi ({host})",
                    data={
                        CONF_HOST: host,
                        CONF_DEVICE_PASSWORD: device_password,
                        CONF_NUM_DOORS: num_doors,
                    },
                )

        return self.async_show_form(
            step_id="user",
            data_schema=STEP_USER_DATA_SCHEMA,
            errors=errors,
        )
