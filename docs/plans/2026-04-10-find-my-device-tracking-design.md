# Find My Device Tracking via ADB Handoff

## Overview

Extend WhisperPair PoC to demonstrate that CVE-2025-36911 escalates from a one-time pairing bypass to persistent location surveillance. After exploiting a vulnerable device, the app hands off to a USB-connected Android phone (via ADB) to complete Google Account registration, making the device trackable through Google's Find My Device network.

## Flow

```
Scan → Exploit → Pair (bluetoothctl) → ADB Handoff → Track Confirmation
```

After the existing exploit chain completes (BR/EDR address extracted, Classic BT paired), a new tracking phase:

1. User clicks "Track via Find My Device" in the UI
2. Backend verifies ADB phone is connected
3. Backend sends ADB commands to pair the Android phone with the target's BR/EDR address
4. Android's Fast Pair service detects the device, writes its own Account Key, registers with Google Account
5. UI confirms registration and provides link to Google Find My Device

## Backend: ADB Manager

### New file: `adb_manager.py`

Lightweight class wrapping ADB shell commands (same pattern as existing `bluetoothctl` usage).

**Methods:**

- `list_devices()` — runs `adb devices -l`, parses output, returns list of `{id, model, status}`
- `get_device_info(device_id)` — runs `adb -s <id> shell getprop` to pull model name, Android version, BT status
- `enable_bluetooth(device_id)` — `adb shell cmd bluetooth_manager enable`
- `pair_device(device_id, br_edr_address)` — triggers Classic BT pairing from the Android phone to the target BR/EDR address. Fallback chain for Android 14:
  1. `adb shell cmd bluetooth_manager pair <MAC>`
  2. `adb shell am start -a android.bluetooth.device.action.PAIRING_REQUEST` intent
  3. `adb shell svc bluetooth` commands
- `verify_paired(device_id, br_edr_address)` — checks paired device list on the phone

**Error handling:** Each step verifies its result before proceeding. ADB commands can fail silently, so outputs are parsed and validated.

### Socket.IO events added to `app.py`

| Event | Direction | Purpose |
|-------|-----------|---------|
| `adb:scan` | client → server | Trigger `list_devices()` |
| `adb:devices` | server → client | Return list of connected phones |
| `adb:select` | client → server | User picks phone (if multiple) |
| `adb:pair` | client → server | Trigger pairing handoff after exploit |
| `adb:status` | server → client | Real-time progress updates |

## Frontend Changes

### TopBar.jsx — ADB Phone Indicator

- Grey dot + "No phone" — no ADB device detected
- Green dot + phone model — connected
- Dropdown to switch if multiple phones detected
- Auto-polls `adb:scan` on app load and every 10 seconds

### ExploitPanel.jsx — Track Button

After successful exploit (ResultCard shows vulnerable + BR/EDR extracted):

- "Track via Find My Device" button appears
- Clicking checks ADB phone connected, then emits `adb:pair`
- LiveLog receives `adb:status` events in existing timeline style:
  - "Enabling Bluetooth on Pixel 7..."
  - "Pairing with AA:BB:CC:DD:EE:FF..."
  - "Verifying registration..."

### ResultCard.jsx — Tracking Confirmation

On success, ResultCard expands with:

- Green checkmark + "Device registered to Find My Device"
- Explanation text of what happened
- "Open Find My Device" button → opens `https://www.google.com/android/find` in new tab
- Collapsible "Learn more" section (educational component)

### Educational Modal — "How Find My Device Tracking Works"

Reuses the StrategySelector.jsx info modal pattern. Accessible from both the Track button area and ResultCard. Content:

1. **Account Key Injection** — WhisperPair wrote a random Account Key. Your Android phone paired and registered its own Account Key with your Google Account.
2. **FMDN Beacons** — The hijacked device now broadcasts Find My Device Network advertisement frames over BLE, derived from the registered Account Key.
3. **Crowd-sourced Location** — Nearby Android devices in the Find Hub network detect these beacons and report them to Google with their GPS coordinates.
4. **Location Query** — The Account Key owner can query Find My Device to see the last reported location.
5. **Security Implications** — CVE-2025-36911 escalates from a one-time pairing bypass to persistent location surveillance. The victim's device is trackable anywhere there are nearby Android phones, with no indication to the victim.

## Technical Notes

- **Android version:** Targeting Android 14, which has solid ADB Bluetooth support
- **ADB pairing fallbacks:** Three approaches in priority order since Android versions handle BT pairing via ADB differently
- **Fast Pair auto-detection:** After ADB pairs the phone with the target, Android's Fast Pair service should automatically detect the device and handle Account Key registration — this is the key assumption to validate during implementation
- **No Google API scraping:** Location data is viewed through Google's own Find My Device web interface, not pulled into the app

## Files to Create/Modify

| File | Action | Purpose |
|------|--------|---------|
| `adb_manager.py` | Create | ADB wrapper class |
| `app.py` | Modify | Add ADB Socket.IO events |
| `frontend/src/components/TopBar.jsx` | Modify | ADB phone indicator |
| `frontend/src/components/ExploitPanel.jsx` | Modify | Track button |
| `frontend/src/components/ResultCard.jsx` | Modify | Tracking confirmation + educational section |
| `frontend/src/components/LiveLog.jsx` | Modify | Handle `adb:status` events in timeline |
| `frontend/src/App.jsx` | Modify | ADB event listeners + state |
| `frontend/src/App.css` | Modify | Styles for new components |
