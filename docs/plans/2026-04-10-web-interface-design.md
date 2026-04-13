# WhisperPair Web Interface Design

## Overview

A web-based dashboard for the WhisperPair-PoC exploit tool, providing real-time device scanning, individual device targeting, and per-strategy exploit selection.

## Architecture

```
React Frontend (Vite, port 5173)
    ├── TopBar        — title, connection status, scan button
    ├── DevicePanel   — scrollable device card list
    └── ExploitPanel  — strategy selector, live log, result card
         │
         │  Socket.IO + REST
         ▼
Flask Backend (Flask-SocketIO, port 5000)
    ├── REST: /api/status, /api/devices, /api/strategies
    ├── Socket.IO events for real-time scan + exploit progress
    └── Imports fast_pair_demo.py directly (no rewrite)
```

## Backend API

### REST Endpoints

| Method | Endpoint          | Purpose                                    |
|--------|-------------------|--------------------------------------------|
| GET    | /api/status       | Backend health + BLE adapter status        |
| GET    | /api/devices      | Return cached discovered devices           |
| GET    | /api/strategies   | Return available strategies + descriptions |

### Socket.IO Events (server → client)

| Event                | Payload                              |
|----------------------|--------------------------------------|
| scan:device_found    | {name, address, rssi, service_data}  |
| scan:complete        | {count, duration}                    |
| exploit:stage        | {stage, message, status}             |
| exploit:result       | {ExploitResult as JSON}              |
| exploit:error        | {message}                            |

### Socket.IO Events (client → server)

| Event          | Payload                             |
|----------------|-------------------------------------|
| scan:start     | {duration?: 10}                     |
| exploit:start  | {address, strategies: string[]}     |
| exploit:stop   | {}                                  |

## Frontend Layout

- **Top Bar** — App title, Socket.IO connection indicator, scan trigger
- **Left Panel (Devices)** — Cards stream in during scan. Each shows name, MAC, RSSI bar, model ID, "Target" button. Border color: grey (untested), orange (in-progress), green (vulnerable), red (not vulnerable)
- **Right Panel (Exploit)** — Selected device summary, 4 strategy checkboxes (RAW_KBP, RAW_WITH_SEEKER, RETROACTIVE, EXTENDED_RESPONSE), execute button, live timeline log, result card

## Tech Stack

**Backend:** Flask, Flask-SocketIO, Flask-CORS, eventlet
**Frontend:** Vite, React, socket.io-client, lucide-react
**State:** useState + useReducer (no external state library)
**Styling:** Custom CSS with CSS variables (dark theme)

## File Structure

```
WhisperPair-PoC/
├── app.py                     # Flask backend
├── frontend/
│   ├── package.json
│   ├── vite.config.js
│   ├── index.html
│   └── src/
│       ├── main.jsx
│       ├── App.jsx
│       ├── App.css
│       ├── socket.js
│       └── components/
│           ├── TopBar.jsx
│           ├── DevicePanel.jsx
│           ├── DeviceCard.jsx
│           ├── ExploitPanel.jsx
│           ├── StrategySelector.jsx
│           ├── LiveLog.jsx
│           └── ResultCard.jsx
```
