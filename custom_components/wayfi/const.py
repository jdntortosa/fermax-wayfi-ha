"""Constants for the Fermax Way-Fi integration."""

DOMAIN = "wayfi"

CONF_HOST = "host"
CONF_PIN = "pin"
CONF_NUM_DOORS = "num_doors"
# Last channel-select offset0 value confirmed to wake this panel's bus
# (see protocol.py CHANNEL_OFFSET0_CURRENT/_FALLBACKS). Stored per config
# entry so a panel that already rotated away from the hardcoded default
# doesn't have to rediscover it on every door press.
CONF_OFFSET0 = "offset0"

DEFAULT_PORT = 5801
DEFAULT_NUM_DOORS = 2

LOCK_CANDADO = 0
