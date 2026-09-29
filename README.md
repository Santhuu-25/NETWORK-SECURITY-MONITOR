# Network Security Monitor

**Real-Time Network Packet Analysis & Security Dashboard**

A professional Security Operations Center (SOC) style real-time network monitoring application built with Python, Flask, Scapy, and Flask-SocketIO.

---

## Architecture & Real-Time Flow

```text
REAL NETWORK TRAFFIC
        ↓
SCAPY (AsyncSniffer in background thread)
        ↓
PYTHON BACKEND (app.py metadata parser)
        ↓
FLASK-SOCKETIO (socketio.emit('packet_update', packet_data))
        ↓
BROWSER SOCKET.IO (dashboard.js: socket.on('packet_update'))
        ↓
LIVE PACKET TABLE, CHARTS & ANIMATED NETWORK MAP
```

---

## Features

- **Real-Time Live Packet Capture**: Non-blocking packet inspection using Scapy raw socket engine in a background thread.
- **WebSocket Streaming**: Ultra-fast live packet metadata streaming via Flask-SocketIO using a unified `packet_update` event.
- **Animated Network Map**: Interactive Canvas topology displaying glowing packet flow particles representing captured network traffic.
- **Defensive Security Detection**: Live detection of high packet rate spikes (>60 pkts/sec) and connection probing / port scan attempts (>=15 ports).
- **Interactive SOC Interface**: Dark cybersecurity visual aesthetic with protocol filters, search, start/stop controls, interface selector, and system status monitors.
- **Live Charting**: Dynamic protocol distribution, packets-per-second velocity, and traffic bandwidth charts powered by Chart.js.
- **Interface Selection**: Auto-detects available host network interfaces (`eth0`, `lo`, `wlan0`, `any`).

---

## Installation & Running on Kali Linux / WSL

### 1. Virtual Environment Setup
```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### 2. Exact Start Command
Packet capture requires root privileges to bind raw socket interfaces:
```bash
sudo ./venv/bin/python app.py
```

### 3. Access Dashboard
Open your browser at:
```text
http://127.0.0.1:5000
```
or
```text
http://localhost:5000
```

---

## Security & Permissions Notice

This application is strictly designed for authorized defensive security monitoring and educational purposes on lab networks or interfaces you own or have explicit permission to monitor. Running packet sniffing on Linux requires root (`sudo`) capabilities to access raw network sockets.
