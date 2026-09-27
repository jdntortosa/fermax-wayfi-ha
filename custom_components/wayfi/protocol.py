"""LAN protocol client for the Fermax Way-Fi video intercom (UMEye/Quvii OEM).

This talks directly to the panel over TCP port 5801 on the local network --
no cloud, no P2P, no vendor app required. Reverse-engineered from real
traffic captures and dynamic instrumentation (Frida) of the official
Android app (com.fermax.wayfi).

Wire format shared by every message on this port:

  Header (20 bytes): b"\\xee\\xee\\xff\\xff" + total_len(u32 LE) + type(2 bytes)
                      + flag(1: 0=request/1=response) + status(1, 0=success)
                      + nonce(u32 LE) + reserved(u32 LE, always 0)
  TLV (command messages only): cmd(u32 LE) + len(u32 LE) + body

Handshake, required before the panel accepts anything else:

  1) HELLO (112 bytes, static/identical across every observed session).
     The panel replies with another 112 bytes carrying a base64 challenge
     at offset 48:84 (with its trailing '=' padding).
  2) LOGIN (561 bytes): username "admin" (offset 20:52) + a 32 hex-char
     hash (offset 52:84), where
         hash = MD5(challenge_base64_AS_RECEIVED + ":" + device_password)
     -- confirmed byte-for-byte via a live Frida hook on the app's own
     MD5 helper: the raw base64 string (padding included, not decoded) is
     concatenated with ":" and the device password.
  3) PLACEHOLDER (52 bytes, static: 32 ASCII '0' characters).

Waking the panel's bus (the "channel-select" / video-open step). This is
a SECOND, independent TCP connection to the same host:port, opened
concurrently with the control connection and BEFORE its login. It does
NOT perform its own HELLO/LOGIN -- it goes straight to a 36-byte packet,
type 0x0221.

What that packet actually is (confirmed by disassembling the app's native
libNewAllStreamParser.so, arm64, 2026-09-27): it is the UMSP ("UMeye
Streaming Protocol") message
    NPC_F_PVM_UMSP_PRO_SendProData_P2_EX_REALPLAY_OPEN
i.e. the "open live video (realplay)" request. Its native signature is
(conn, uint32, uint16, uint16, uint32), which maps onto the 16-byte body
as four fields:

  - body[0:4]  = param1 (uint32) = (session_field << 16) | 0x0003
      * The low byte, body[0] (absolute offset 20), is CHANNEL_OFFSET0.
        It is the low byte of the realplay-open stream parameter -- NOT a
        registered-client index or a device id, despite once looking like
        one. Its value is currently 0x03; a capture from months ago had
        0x02, and the panel now rejects 0x02 with status=0x06. The exact
        meaning of the 2-vs-3 enum was not fully resolved from the caller;
        the most plausible reading is a media bitmask (bit0=video,
        bit1=audio -> 0x03 = video+audio, consistent with H264 *and* G711
        both arriving on this connection), but that is a hypothesis, not
        confirmed. Whether the change was triggered by an app update
        (recompiled constant) or a panel firmware change is unknown.
      * The high 2 bytes, body[2:4] (absolute 22:24), are SESSION_FIELD:
        a literal copy of the 2-byte field at offset 318 of the CONTROL
        connection's LOGIN response (right before the ASCII "DVR"). This
        is what binds this unauthenticated connection to the logged-in
        session. Without it the panel rejects with status=0x06.
  - body[4:6]  = param2 (uint16) = channel/panel: 0x0000 = door 1,
    0x0001 = door 2. body[4] is PANEL_CHANNEL_OFFSET. Confirmed 4/4.
  - body[6:8]  = param3 (uint16) = fixed 0x0001.
  - body[8:12] = param4 (uint32) = fixed 0x00000001.
  - body[12:16] are 0 in the request; the panel fills them in its reply
    (04 00 <2 bytes>, apparently a media-session id/port it assigns).

Because the CHANNEL_OFFSET0 value has already shifted once (0x02 -> 0x03)
and may shift again, open_door() does not trust a single hardcoded value:
it tries the last known-good one first (persisted per config entry, see
CONF_OFFSET0), and on rejection or a silent bus (accepted but no real
video/audio follows) rotates through the rest of CHANNEL_OFFSET0_RANGE
until one both gets accepted AND wakes the bus. If the whole range is
exhausted it fails fast (returns success=False WITHOUT sending the open
command) rather than reporting a false "success" -- that means the real
value moved outside 0x00-0x09 and needs a fresh packet capture.

A status=0x00 accept is not enough on its own: the outdoor unit sits on
an internal bus that is not always "awake". Real video/audio starts
flowing over this same second connection a few seconds later (tens of KB:
an H264 keyframe followed by shrinking P frames) once the bus really
wakes that panel up. Only then does the door-open command on the control
connection actually drive the physical relay.

Then, on the control connection: a handful of "pre-open" queries copied
verbatim from a real session (not confirmed as strictly required, but
included because the panel accepts the open command reliably with them),
followed by the open command itself: TLV cmd=2046 ("open lock"), 36-byte
body = 00 00 lockNum 00 + device_password(15 bytes ASCII, zero-padded) +
17 zero bytes.
"""

from __future__ import annotations

import hashlib
import logging
import socket
import struct
import time

_LOGGER = logging.getLogger(__name__)

MAGIC = bytes.fromhex("eeeeffff")

HELLO_112 = bytes.fromhex(
    "eeeeffff700000000101000000000000000000000101020103010000000000000000000000000000000000000300000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
)
assert len(HELLO_112) == 112, len(HELLO_112)

PLACEHOLDER_52 = bytes.fromhex(
    "eeeeffff340000000100000000000000000000003030303030303030303030303030303030303030303030303030303030303030"
)
assert len(PLACEHOLDER_52) == 52, len(PLACEHOLDER_52)

# UMSP EX_REALPLAY_OPEN packet (type 0x0221). See the module docstring for
# the full field breakdown recovered from the native library.
# CHANNEL_TYPE_OFFSET, PANEL_CHANNEL_OFFSET and SESSION_FIELD_OFFSET are
# absolute offsets into this 36-byte packet.
VIDEO_START_36_TEMPLATE = bytearray.fromhex(
    "eeeeffff2400000021020000000000000000000003000000000001000100000000000000"
)
assert len(VIDEO_START_36_TEMPLATE) == 36, len(VIDEO_START_36_TEMPLATE)
CHANNEL_TYPE_OFFSET = 20
PANEL_CHANNEL_OFFSET = 24
SESSION_FIELD_OFFSET = 22

# CHANNEL_OFFSET0 = low byte of the realplay-open stream parameter (see
# docstring). The panel's accepted value has changed once already
# (0x02 -> 0x03) and may change again. CHANNEL_OFFSET0_CURRENT is the
# hardcoded default used when a config entry hasn't discovered/persisted
# its own value yet (see CONF_OFFSET0 in const.py); CHANNEL_OFFSET0_RANGE
# is the full space open_door() rotates through.
CHANNEL_OFFSET0_CURRENT = 0x03
CHANNEL_OFFSET0_RANGE = tuple(range(0x00, 0x0A))
CHANNEL_WAKE_TIMEOUT = 8.0


def _offset0_candidates(start: int) -> list[int]:
    """Candidate order for a rotation attempt: `start` (the panel's last
    known-good value, or CHANNEL_OFFSET0_CURRENT if none is known yet)
    first, then the rest of CHANNEL_OFFSET0_RANGE.
    """
    candidates = [start]
    candidates.extend(v for v in CHANNEL_OFFSET0_RANGE if v != start)
    return candidates

CMD_OPEN_LOCK = 2046

# Pre-open queries the real app sends on the control connection, byte for
# byte identical regardless of which door was selected.
PRE_OPEN_QUERIES = [
    bytes.fromhex("eeeeffff1d000000010a0000000016a700000000fa0700000100000000"),
    bytes.fromhex(
        "eeeeffff3c000000010a00000000a7c500000000a0070000200000000000000000000000000000000000000000000000000000000000000000000000"
    ),
    bytes.fromhex("eeeeffff1d000000010a000000002a3200000000000800000100000000"),
    bytes.fromhex("eeeeffff1d000000010a00000000f73500000000f80700000100000000"),
]

DEVICE_GROUP_ID = b"G0021"
LOGIN_RESP_SESSION_FIELD_OFFSET = 318


class WayfiConnectionError(Exception):
    """Raised when the panel cannot be reached or rejects the login."""


def derive_device_password(pin: str) -> str:
    """Derive the protocol-level "device password" from the PIN the user
    enters in the vendor app (e.g. "2108").

    Reverse-engineered by statically disassembling the app's own
    NPC_TOOLS_MD5_MD5Encrypt(char* out, char* in) in
    libNewAllStreamParser.so, and confirmed against a real captured
    value (pin "2108" -> "n4DVjrgh"):

      1) Compute a plain MD5 digest of `pin` (16 bytes).
      2) For each of the 8 consecutive byte pairs in that digest,
         sum the pair and reduce it modulo 62.
      3) Map 0-9 to '0'-'9', 10-35 to 'A'-'Z', 36-61 to 'a'-'z'.

    The vendor app then uses this 8-character result (not the PIN
    itself) both as the LOGIN password and inside the open-lock command
    body.
    """
    digest = hashlib.md5(pin.encode()).digest()
    chars = []
    for i in range(8):
        value = (digest[2 * i] + digest[2 * i + 1]) % 62
        if value <= 9:
            chars.append(chr(0x30 + value))
        elif value <= 35:
            chars.append(chr(0x37 + value))
        else:
            chars.append(chr(0x3D + value))
    return "".join(chars)


def build_video_start(panel: int, session_field: bytes, offset0: int = CHANNEL_OFFSET0_CURRENT) -> bytes:
    if panel not in (0, 1):
        raise ValueError("panel must be 0 (door 1) or 1 (door 2)")
    if len(session_field) != 2:
        raise ValueError("session_field must be 2 bytes")
    pkt = bytearray(VIDEO_START_36_TEMPLATE)
    pkt[CHANNEL_TYPE_OFFSET] = offset0
    pkt[PANEL_CHANNEL_OFFSET] = panel
    pkt[SESSION_FIELD_OFFSET:SESSION_FIELD_OFFSET + 2] = session_field
    return bytes(pkt)


def _recv_exact(sock: socket.socket, n: int) -> bytes:
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise WayfiConnectionError(f"connection closed, expected {n} bytes, got {len(buf)}")
        buf += chunk
    return buf


def _frame_header(total_len: int, type_bytes: bytes, is_response: bool, nonce: int = 0) -> bytes:
    return (
        MAGIC
        + struct.pack("<I", total_len)
        + type_bytes
        + bytes([1 if is_response else 0, 0])
        + struct.pack("<I", nonce)
        + bytes(4)
    )


def _build_login_561(username: str, pwd_hash_hex: str) -> bytes:
    header = _frame_header(561, bytes([0x05, 0x01]), is_response=False)
    body = bytearray(561 - len(header))
    body[0:32] = username.encode("ascii").ljust(32, b"\x00")
    body[32:64] = pwd_hash_hex.encode("ascii").ljust(32, b"\x00")
    # Fixed fields observed in every real request, not confirmed one by
    # one but present in every captured session.
    body[288:292] = struct.pack("<I", 1)
    body[292:296] = struct.pack("<I", 5)
    body[-5:] = DEVICE_GROUP_ID
    packet = header + bytes(body)
    assert len(packet) == 561
    return packet


def _extract_challenge_b64(resp_112: bytes) -> str:
    raw = resp_112[48:84].rstrip(b"\x00")
    return raw.decode("ascii")


def _compute_login_hash(challenge_b64: str, password: str) -> str:
    return hashlib.md5(f"{challenge_b64}:{password}".encode()).hexdigest()


def _perform_login(sock: socket.socket, device_password: str) -> bytes:
    """Run HELLO+LOGIN on `sock`, leaving the connection authenticated.

    Returns the full 561-byte LOGIN response. Raises WayfiConnectionError
    on failure.
    """
    sock.sendall(HELLO_112)
    hello_resp = _recv_exact(sock, 112)
    challenge_b64 = _extract_challenge_b64(hello_resp)
    pwd_hash = _compute_login_hash(challenge_b64, device_password)
    sock.sendall(_build_login_561("admin", pwd_hash))
    login_resp = _recv_exact(sock, 561)
    status = login_resp[11]
    if status != 0:
        raise WayfiConnectionError(f"login rejected, status={status:#04x}")
    return login_resp


def _extract_session_field(login_resp: bytes) -> bytes:
    return login_resp[LOGIN_RESP_SESSION_FIELD_OFFSET:LOGIN_RESP_SESSION_FIELD_OFFSET + 2]


def _build_open_packet(lock_num: int, device_password: str) -> bytes:
    if lock_num not in (0, 1):
        raise ValueError("lock_num must be 0 or 1")
    password_bytes = device_password.encode("ascii")
    if len(password_bytes) > 15:
        raise ValueError("device_password must fit in 15 bytes")
    body = bytes([0, 0, lock_num, 0]) + password_bytes.ljust(15, b"\x00") + bytes(17)
    assert len(body) == 36
    tlv = struct.pack("<II", CMD_OPEN_LOCK, len(body)) + body
    header = _frame_header(20 + len(tlv), bytes([0x01, 0x0A]), is_response=False, nonce=0x12345678)
    packet = header + tlv
    assert len(packet) == 64
    return packet


def test_connection(host: str, port: int, device_password: str) -> None:
    """Connect to the panel and run HELLO+LOGIN only, to validate the host
    and device password during config flow setup. Raises
    WayfiConnectionError on any failure (unreachable host, wrong
    password, ...); returns None on success.
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(5.0)
    try:
        sock.connect((host, port))
        _perform_login(sock, device_password)
    except OSError as exc:
        raise WayfiConnectionError(f"cannot reach {host}:{port}: {exc}") from exc
    finally:
        sock.close()


def _try_channel_wake(channel_sock: socket.socket, panel: int, session_field: bytes, offset0: int) -> int:
    """Send a channel-select packet on an already-open `channel_sock` and
    wait for real video/audio to confirm the bus woke up. Returns the
    number of bytes received (0 = rejected or bus stayed silent).
    """
    channel_sock.sendall(build_video_start(panel, session_field, offset0))
    try:
        channel_resp = channel_sock.recv(4096)
    except socket.timeout:
        return 0
    if len(channel_resp) < 12 or channel_resp[11] != 0:
        return 0

    channel_sock.settimeout(CHANNEL_WAKE_TIMEOUT)
    total_channel_bytes = 0
    deadline = time.time() + CHANNEL_WAKE_TIMEOUT
    while time.time() < deadline:
        try:
            chunk = channel_sock.recv(4096)
            if not chunk:
                break
            total_channel_bytes += len(chunk)
        except socket.timeout:
            break
    return total_channel_bytes


def _attempt_open(host: str, port: int, panel: int, device_password: str, lock: int, offset0: int) -> bool | None:
    """Run ONE full, self-contained attempt: fresh control + channel
    connections opened concurrently and BEFORE login (the exact timing
    confirmed to reliably wake the bus -- a regression was found and
    reverted where reconnecting the channel *after* login made door 1
    stop opening physically even though the protocol still reported
    success), login, channel-select with `offset0`, and -- only if the
    bus actually wakes up -- the open command.

    Returns True/False for a real open attempt (bus woke up), or None if
    this `offset0` was rejected or the bus stayed silent -- the caller
    should then retry with a different candidate, each getting this exact
    same known-good timing (never a bare reconnect of just the channel
    socket after an existing login, which is not verified to work).
    """
    control_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    control_sock.settimeout(5.0)
    control_sock.connect((host, port))

    channel_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    channel_sock.settimeout(5.0)
    channel_sock.connect((host, port))

    try:
        try:
            login_resp = _perform_login(control_sock, device_password)
        except WayfiConnectionError as exc:
            _LOGGER.error("Control connection login failed: %s", exc)
            return False

        control_sock.sendall(PLACEHOLDER_52)
        _recv_exact(control_sock, 52)

        session_field = _extract_session_field(login_resp)
        _LOGGER.debug("Selecting panel %d, session_field=%s, offset0=%#04x", panel, session_field.hex(), offset0)
        video_bytes = _try_channel_wake(channel_sock, panel, session_field, offset0)
        _LOGGER.debug("Channel offset0=%#04x -> %d bytes", offset0, video_bytes)
        if video_bytes == 0:
            return None

        for query in PRE_OPEN_QUERIES:
            control_sock.sendall(query)
            try:
                control_sock.recv(4096)
            except socket.timeout:
                _LOGGER.warning("Pre-open query got no response (timeout)")

        control_sock.sendall(_build_open_packet(lock, device_password))
        open_resp = _recv_exact(control_sock, 29)
        result_byte = open_resp[28]
        if result_byte == 0:
            _LOGGER.debug("Open command succeeded (result byte = 0x00)")
            return True
        _LOGGER.warning("Open command possibly failed (result byte = %#04x)", result_byte)
        return False
    finally:
        control_sock.close()
        channel_sock.close()


def open_door(
    host: str, port: int, panel: int, device_password: str, lock: int = 0,
    offset0_start: int = CHANNEL_OFFSET0_CURRENT,
) -> tuple[bool, int | None]:
    """Run the full protocol (login, panel selection, wait for real video,
    open command) and return (success, offset0_used).

    `offset0_start` should be the last value confirmed to work for this
    specific panel (persisted by the caller -- see CONF_OFFSET0 in
    const.py), falling back to CHANNEL_OFFSET0_CURRENT if none is known
    yet. It is tried first; if the panel rejects it or the bus stays
    silent, this rotates through the rest of CHANNEL_OFFSET0_RANGE, each
    as a full independent attempt (own connections + own login) so every
    candidate gets the identical, confirmed-good connection timing --
    fail fast (success=False) only once every candidate has been tried
    without waking the bus. `offset0_used` is the value that worked (the
    caller should persist it if it differs from what it passed in), or
    None if nothing woke the bus.

    This is a *blocking* call (plain sockets, several seconds of wait built
    in) -- callers running inside Home Assistant's event loop must run it
    via `hass.async_add_executor_job`.
    """
    candidates = _offset0_candidates(offset0_start)

    result = _attempt_open(host, port, panel, device_password, lock, candidates[0])
    if result is not None:
        return result, candidates[0]

    _LOGGER.warning(
        "offset0=%#04x was rejected or the bus stayed silent; trying other "
        "values (each a full independent attempt).",
        candidates[0],
    )
    for offset0 in candidates[1:]:
        result = _attempt_open(host, port, panel, device_password, lock, offset0)
        if result is not None:
            _LOGGER.warning("Recovered using offset0=%#04x.", offset0)
            return result, offset0

    _LOGGER.error(
        "Panel did not wake up for any candidate offset0 value (%s) -- the "
        "accepted value likely moved outside this range; a fresh packet "
        "capture is needed.",
        ", ".join(f"{c:#04x}" for c in candidates),
    )
    return False, None
