"""Button entities for the Fermax Way-Fi integration.

Each door is a momentary "open" action, not a stateful lock: this
protocol has no way to read back whether the physical relay is currently
engaged, so a `button` (fire-and-forget) is the honest representation --
see the integration's config flow / README for the reasoning.
"""

from __future__ import annotations

import logging

from homeassistant.components.button import ButtonEntity
from homeassistant.config_entries import ConfigEntry
from homeassistant.const import CONF_HOST
from homeassistant.core import HomeAssistant
from homeassistant.exceptions import HomeAssistantError
from homeassistant.helpers.entity import DeviceInfo
from homeassistant.helpers.entity_platform import AddEntitiesCallback

from .const import CONF_NUM_DOORS, CONF_PIN, DEFAULT_PORT, DOMAIN, LOCK_CANDADO
from .protocol import derive_device_password, open_door

_LOGGER = logging.getLogger(__name__)


async def async_setup_entry(
    hass: HomeAssistant,
    entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    """Set up one button per configured door."""
    host = entry.data[CONF_HOST]
    device_password = derive_device_password(entry.data[CONF_PIN])
    num_doors = entry.data[CONF_NUM_DOORS]

    async_add_entities(
        WayfiDoorButton(entry, host, device_password, door_number)
        for door_number in range(1, num_doors + 1)
    )


class WayfiDoorButton(ButtonEntity):
    """A momentary button that opens one door of the panel."""

    _attr_has_entity_name = True

    def __init__(self, entry: ConfigEntry, host: str, device_password: str, door_number: int) -> None:
        self._host = host
        self._device_password = device_password
        self._door_number = door_number
        self._panel = door_number - 1  # 0 = door 1, 1 = door 2

        self._attr_unique_id = f"{entry.entry_id}_door_{door_number}"
        self._attr_translation_key = "open_door"
        self._attr_translation_placeholders = {"door_number": str(door_number)}
        self._attr_icon = "mdi:door-open"
        self._attr_device_info = DeviceInfo(
            identifiers={(DOMAIN, entry.entry_id)},
            name=f"Fermax Way-Fi ({host})",
            manufacturer="Fermax (UMEye/Quvii OEM)",
            model="Way-Fi video intercom",
        )

    async def async_press(self) -> None:
        """Open this door."""
        success = await self.hass.async_add_executor_job(
            open_door, self._host, DEFAULT_PORT, self._panel, self._device_password, LOCK_CANDADO
        )
        if not success:
            raise HomeAssistantError(
                f"El panel en {self._host} no confirmo la apertura de la puerta {self._door_number} "
                "(el bus no desperto o el comando de apertura fallo -- ver logs de la integracion)"
            )
