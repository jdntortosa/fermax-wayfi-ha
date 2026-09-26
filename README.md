# Fermax Way-Fi (UMEye/Quvii) for Home Assistant

A Home Assistant integration for the **Fermax Way-Fi** video intercom
(app `com.fermax.wayfi`) — an OEM device from the Chinese **UMEye/Quvii**
platform, sold under the Fermax brand. It is **not** Fermax Blue/DUOX
PLUS; see [`bvis/fermax-blue-hass`](https://github.com/bvis/fermax-blue-hass)
for that different product line.

This integration talks **directly to the panel over the local network**
(TCP port 5801) — no cloud account, no vendor app, no P2P/NAT traversal
required. It opens a `button` entity per configured door.

## Why this exists

The vendor app is the only official way to open the doors, and it has no
public API. The LAN protocol used here was reverse-engineered from real
traffic captures and dynamic instrumentation (Frida) of the Android app.
See [`custom_components/wayfi/protocol.py`](custom_components/wayfi/protocol.py)
for the full protocol writeup and the exact byte offsets involved.

## What it does (and doesn't)

- Provides one `button.open_door_N` entity per door (1 or 2), which
  triggers the panel's relay for that door.
- There is **no state**: this protocol has no way to read back whether a
  door is currently open — a `button` is the honest representation, not
  a `lock` pretending to know something it doesn't.
- Each press takes roughly 10 seconds: the panel's outdoor unit sits on
  an internal bus that isn't always awake, and this integration has to
  wait for real video/audio to start flowing before the open command
  actually reaches the physical relay (see the protocol docstring for
  why).

## Installation

### Via HACS (custom repository)

1. HACS → the "⋮" menu (top right) → **Custom repositories**.
2. Add `https://github.com/jdntortosa/fermax-wayfi-ha`, category
   **Integration**.
3. Install **Fermax Way-Fi (UMEye/Quvii)**, then restart Home Assistant.
4. Settings → Devices & Services → **Add Integration** → search for
   "Fermax Way-Fi".

### Manual

Copy `custom_components/wayfi/` into your Home Assistant `config/custom_components/`
directory, then restart Home Assistant and add the integration as above.

## Configuration

The config flow asks for:

| Field | Meaning |
|---|---|
| Panel IP address | The panel's LAN IP address (must be reachable from Home Assistant) |
| App password | The same PIN/password you already use in the vendor app to unlock the panel — enter it as-is |
| Number of doors | 1 or 2 — how many `button` entities to create |

The vendor app never sends this PIN over the wire as-is: it derives an
8-character value from it first (see
[`protocol.py`](custom_components/wayfi/protocol.py), function
`derive_device_password`, reverse-engineered from the app's own native
code) and uses that derived value in the LAN protocol. This integration
does the same derivation internally, so you only ever need the PIN you
already know.

## Credits

Protocol reverse-engineered from the `com.fermax.wayfi` Android app.
Related prior work: [`totoantibes/golmar-quvii-ha`](https://github.com/totoantibes/golmar-quvii-ha)
(a sibling UMEye/Quvii-family integration using the newer cloud API, not
the LAN protocol used here).

## License

MIT — see [LICENSE](LICENSE).
