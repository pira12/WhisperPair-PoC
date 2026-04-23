# WhisperPair - CVE-2025-36911

![Type](https://img.shields.io/badge/Exploit-Protocol%20Logic-red)
![Python](https://img.shields.io/badge/Python-3.10%2B-blue)
![Status](https://img.shields.io/badge/Status-PoC-orange)
![License](https://img.shields.io/badge/License-MIT-blue)

**WhisperPair** is a research proof-of-concept that explores a pairing-mode-bypass weakness in the **Google Fast Pair Service (GFPS)**, tracked under the research identifier **CVE-2025-36911**. It includes a CLI exploit engine, a real-time web dashboard, and an Android companion app for scanning, testing, and demonstrating the impact against devices you own.

**Key insight:** Affected devices accept raw, unencrypted Key-Based Pairing requests even when they are **not** in pairing mode - no Anti-Spoofing Public Key required.

---

> ## ⚠️ Read this before running anything
>
> This repository contains working exploit code that can force-pair with
> Bluetooth devices and stream their microphone audio without user
> consent.
>
> - **Authorized use only.** Run this only against devices you own or
>   have explicit, written permission to test.
> - **Eavesdropping is regulated.** Capturing another person's audio is
>   illegal in most jurisdictions, regardless of which hardware you ran
>   the tool from.
> - **No warranty.** The maintainers accept no responsibility for damage,
>   data loss, or legal consequences arising from use of this code.
> - **Research identifier.** "CVE-2025-36911" is the identifier this PoC
>   tracks against. Verify its current status on the
>   [CVE Program](https://www.cve.org/) or [NVD](https://nvd.nist.gov/)
>   before treating it as a confirmed, published vulnerability.
>
> Full terms in [`DISCLAIMER.md`](DISCLAIMER.md). Vulnerability reporting
> process in [`SECURITY.md`](SECURITY.md).

## Vulnerability Overview (CVE-2025-36911)

The Fast Pair protocol contains an **Improper Access Control** vulnerability that allows an attacker to:

1. Send raw Key-Based Pairing (KBP) requests to devices NOT in pairing mode
2. Bypass the standard cryptographic handshake requirements
3. Extract the device's BR/EDR (Classic Bluetooth) address from the response
4. Force-pair via Classic Bluetooth without user interaction
5. Inject an arbitrary Account Key to hijack the device

### Impact

Once exploited, an attacker within BLE range (~30m) can:
- **Force-pair** with the target device without user consent
- **Hijack audio** via HFP/A2DP profiles (microphone access)
- **Eavesdrop** on the device's microphone in real time
- **Track the device** via Find My Device / Find Hub networks
- **Persistent access** through injected Account Keys
- **Cross-transport bonding** via CTKD-derived BR/EDR link keys

## Architecture

```
WhisperPair-PoC/
├── fast_pair_demo.py       # Core exploit engine (CLI)
├── app.py                  # Flask + Socket.IO backend (web interface)
├── adb_manager.py          # ADB wrapper for Android phone pairing
├── ctkd.py                 # Cross-Transport Key Derivation (BLE LTK → BR/EDR Link Key)
├── fmdn_scanner.py         # Find My Device Network beacon scanner
├── known_devices.py        # Device fingerprint database with quirk flags
├── test_fast_pair_demo.py  # Unit tests for exploit engine
├── test_adb_manager.py     # Unit tests for ADB manager
├── requirements.txt        # Python dependencies
├── frontend/               # React (Vite) web dashboard
│   └── src/
│       ├── App.jsx
│       ├── socket.js
│       └── components/
│           ├── TopBar.jsx
│           ├── DevicePanel.jsx
│           ├── DeviceCard.jsx
│           ├── ExploitPanel.jsx
│           ├── StrategySelector.jsx
│           ├── LiveLog.jsx
│           ├── ResultCard.jsx
│           ├── TrackingPrereqs.jsx
│           └── EavesdropCard.jsx
└── android/                # Android companion app
    └── app/src/main/java/com/whisperpair/companion/
        ├── FastPairActivity.java
        └── EavesdropActivity.java
```

### Core Exploit Engine (`fast_pair_demo.py`)

The CLI tool that implements the full exploit chain:

1. **BLE Scanning** - Discovers Fast Pair devices by the `0xFE2C` service UUID
2. **GATT Connection** - Connects to the target with retry and exponential backoff
3. **MTU Negotiation** - Requests optimal MTU for reliable GATT operations
4. **Model ID Fingerprinting** - Reads the device Model ID characteristic
5. **KBP Injection** - Sends Key-Based Pairing requests using multiple strategies
6. **Response Parsing** - Extracts the BR/EDR address using 5 parsing strategies (standard, extended, decrypted, brute-force decrypted, raw brute-force)
7. **Classic BT Pairing** - Pairs via `bluetoothctl`
8. **Account Key Injection** - Writes an AES-128-ECB encrypted Account Key

### Web Dashboard (`app.py` + `frontend/`)

A Flask + Socket.IO backend serving a React frontend that provides:

- **Real-time device scanning** with enriched metadata from the known devices database
- **Live exploit execution** with stage-by-stage progress via WebSocket events
- **Vulnerability test mode** - non-invasive test that sends KBP requests but skips Account Key writing and Classic BT pairing
- **ADB integration** - detects connected Android phones and triggers Bluetooth pairing to register exploited devices with Find My Device
- **Strategy selection** - choose which exploit strategies to attempt
- **Device tracking** - two modes for Find My Device registration:
  - **Phone mode** - launches the Android companion app via ADB to bond and register the device
  - **Laptop mode** - derives a BR/EDR Link Key from the BLE LTK via CTKD and injects it into BlueZ
- **Audio eavesdropping** - records the target device's microphone via HFP/A2DP after bonding, with real-time PCM audio streaming to the browser

Socket.IO events: `scan:start`, `scan:device_found`, `scan:complete`, `exploit:start`, `exploit:stage`, `exploit:notification`, `exploit:result`, `exploit:stop`, `vuln_test:start`, `adb:scan`, `adb:select`, `adb:pair`, `track:start`, `track:status`, `eavesdrop:start`, `eavesdrop:stop`, `eavesdrop:status`, `eavesdrop:audio`

REST endpoints: `GET /api/status`, `GET /api/devices`, `GET /api/strategies`, `GET /api/known-devices`

### Cross-Transport Key Derivation (`ctkd.py`)

Implements CTKD per Bluetooth Core Spec Vol 3, Part H, Section 2.4.2.5 to derive a BR/EDR Link Key from a BLE Long Term Key (LTK). This enables Classic Bluetooth bonding from an existing BLE bond without the device being in pairing mode.

1. Extract LTK from BlueZ config (`/var/lib/bluetooth/<adapter>/<device>/info`)
2. Derive Link Key: `h6(h7("ble salt", LTK), "Link Key")` using AES-CMAC
3. Inject Link Key into BlueZ config for the BR/EDR address
4. Restart `bluetoothd` to load the new key
5. Connect via Classic BT using the derived key

### FMDN Beacon Scanner (`fmdn_scanner.py`)

Scans for Find My Device Network (FMDN) beacons matching the Account Key injected during exploitation. After the Account Key is written, the target device begins broadcasting FMDN advertisements with Ephemeral Identifiers (EIDs) derived from the key.

Detects beacons via:
- FMDN service UUID (`0xFCAE`) with frame type `0x40`
- Fast Pair service UUID (`0xFE2C`) with Account Key filter
- Any advertisement from the known device address

### ADB Manager (`adb_manager.py`)

Wraps Android Debug Bridge commands to:

- List connected Android devices with model and Android version info
- Enable Bluetooth on the phone
- Pair the phone with an exploited target (tries `bluetooth_manager pair`, falls back to pairing intent)
- Verify the target appears in the phone's bonded device list

### Android Companion App (`android/`)

A minimal Android app (API 31+, target 35) that runs the exploit directly on the phone:

- **FastPairActivity** - Receives a BLE address via intent, runs KBP exploit, bonds via Classic Bluetooth
- **EavesdropActivity** - Uses the HFP profile to access the target device's microphone

Triggered from the backend via:
```bash
adb shell am start -a com.whisperpair.PAIR --es address AA:BB:CC:DD:EE:FF
```

### Known Devices Database (`known_devices.py`)

Contains fingerprints for 25+ devices from Google, JBL, Sony, Samsung, Bose, Nothing, OnePlus, and Jabra. Each entry includes:

- Model ID, name, manufacturer, device type
- **Quirk flags** that adjust exploit behavior:
  - `QUIRK_NEEDS_SEEKER_ADDR` - Include seeker address in KBP request
  - `QUIRK_NEEDS_BONDING_FLAG` - Set bonding flag in KBP request
  - `QUIRK_SLOW_GATT` - Increase GATT timeouts
  - `QUIRK_MTU_83` - Require MTU negotiation to 83 bytes
  - `QUIRK_RETRY_CONNECT` - Retry after initial connection failure
  - `QUIRK_NO_ACCOUNT_KEY` - Skip Account Key write step
  - `QUIRK_EXTENDED_RESPONSE_ONLY` - Only respond to extended format requests

## Exploit Strategies

| Strategy | Flag Byte | Description |
|----------|-----------|-------------|
| `RAW_KBP` | `0x11` | Raw unencrypted request with initiate bonding + extended response flags. Most common for vulnerable devices. Salt becomes the shared secret. |
| `RAW_WITH_SEEKER` | `0x11` | Same as RAW_KBP but includes seeker address for bonding initiation. |
| `RETROACTIVE` | `0x0A` | Sets bonding + retroactive pairing bits. Includes seeker address. Bypasses some firmware checks. |
| `EXTENDED_RESPONSE` | `0x10` | Requests extended response format only. Salt becomes the shared secret. |

Strategies are tried in order until one is accepted by the device.

## GFPS Characteristics

| Characteristic | UUID | Purpose |
|---------------|------|---------|
| Model ID | `fe2c1233-8366-4814-8eb0-01de32100bea` | Device fingerprinting |
| Key-Based Pairing | `fe2c1234-8366-4814-8eb0-01de32100bea` | KBP request/response |
| Passkey | `fe2c1235-8366-4814-8eb0-01de32100bea` | Passkey verification |
| Account Key | `fe2c1236-8366-4814-8eb0-01de32100bea` | Account Key injection vector |

### KBP Request Format (16 bytes)

| Byte | Field | Description |
|------|-------|-------------|
| 0 | Message Type | `0x00` = KBP Request |
| 1 | Flags | Strategy-dependent (see table above) |
| 2-7 | Provider Address | Target BLE MAC (6 bytes) |
| 8-15 | Salt / Seeker+Salt | Random bytes (salt becomes shared secret for response decryption) |

## Installation

### Backend

```bash
# Create virtual environment (recommended)
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

### Frontend

```bash
cd frontend
npm install
```

### Android Companion App (optional)

```bash
cd android
./gradlew assembleDebug
adb install app/build/outputs/apk/debug/app-debug.apk
```

## Usage

### CLI

```bash
# Auto-scan and exploit the nearest Fast Pair device
python3 fast_pair_demo.py

# Target a specific device by MAC address
python3 fast_pair_demo.py AA:BB:CC:DD:EE:FF
```

Results are saved to a timestamped JSON file: `whisperpair_result_<MAC>_<timestamp>.json`

### Web Dashboard

```bash
# Start the backend (port 5000)
python3 app.py

# Start the frontend dev server (separate terminal)
cd frontend
npm run dev
```

Then open the frontend URL in your browser. The dashboard connects to the backend via Socket.IO.

### FMDN Beacon Scanner

After a successful exploit with Account Key injection, scan for the device's FMDN beacons:

```bash
python3 fmdn_scanner.py
```

### Example CLI Output

```
╔══════════════════════════════════════════════════════════╗
║  WhisperPair PoC - CVE-2025-36911                        ║
║  Fast Pair Pairing Mode Bypass                           ║
╚══════════════════════════════════════════════════════════╝

[*] Scanning for Fast Pair devices (10s)...
[+] Found: Pixel Buds Pro (AA:BB:CC:DD:EE:FF) RSSI: -45

[!] KBP WRITE ACCEPTED - Device is VULNERABLE!
[+] BR/EDR Address: AA:BB:CC:DD:EE:FF
[+] Account Key written successfully!
[+] Pairing successful!
```

## Running Tests

```bash
python3 -m pytest test_fast_pair_demo.py test_adb_manager.py -v
```

## Prerequisites

- **Linux** with BlueZ stack (for `bluetoothctl` pairing and CTKD key injection)
- **Python 3.10+**
- **Bluetooth adapter** with BLE support
- **CAP_NET_RAW** capability (for CTKD raw HCI socket operations)
- **ADB** (optional, for Android phone pairing / Find My Device tracking)
- **Node.js** (optional, for the web dashboard frontend)
- **Android SDK** (optional, for building the companion app)

## References

- CVE-2025-36911 - look up the current status on the [CVE Program](https://www.cve.org/CVERecord?id=CVE-2025-36911) or [NVD](https://nvd.nist.gov/vuln/detail/CVE-2025-36911) before citing
- [Google Fast Pair Specification](https://developers.google.com/nearby/fast-pair/spec)
- [Bluetooth Core Spec - CTKD](https://www.bluetooth.com/specifications/specs/core-specification-6-0/) (Vol 3, Part H, Section 2.4.2.5)

## Reporting issues

- Bugs in this PoC: open a GitHub issue.
- Security issues in this PoC or in third-party devices discovered while using it: see [`SECURITY.md`](SECURITY.md).

## Acknowledgements

Initial groundwork by **Bas Levering**, who kicked the project off. Later
work and the public release are maintained by the WhisperPair Contributors.

## License

MIT License - see [`LICENSE`](LICENSE). Released for authorized security
research and education only; see [`DISCLAIMER.md`](DISCLAIMER.md) for the
full terms of use.
