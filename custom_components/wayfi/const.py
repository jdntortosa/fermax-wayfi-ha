"""Constants for the Fermax Way-Fi integration."""

DOMAIN = "wayfi"

CONF_HOST = "host"
CONF_PIN = "pin"
CONF_NUM_DOORS = "num_doors"
# Last channel-select offset0 value confirmed to wake this panel's bus
# (see protocol.py CHANNEL_OFFSET0_CURRENT/_RANGE). Stored per config
# entry; normally the value comes from the LOGIN response, this is only
# the starting point for the rotation safety net if that ever fails.
CONF_OFFSET0 = "offset0"

DEFAULT_PORT = 5801
DEFAULT_NUM_DOORS = 2

LOCK_CANDADO = 0
