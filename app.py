import os
import sys
import time
import queue
import threading
from flask import Flask, render_template, jsonify, request
from flask_socketio import SocketIO, emit
from network_sniffer import NetworkSniffer

app = Flask(__name__)
app.config['SECRET_KEY'] = 'codealpha-network-monitor-secret'
socketio = SocketIO(app, cors_allowed_origins="*", async_mode="threading")

# Queue to decouple Scapy packet capture from SocketIO emissions
packet_queue = queue.Queue(maxsize=2000)

def handle_new_packet(packet_data):
    proto = packet_data.get('protocol', 'PACKET')
    src = packet_data.get('source_ip', '-')
    dst = packet_data.get('destination_ip', '-')
    print(f"[PACKET] {proto} {src} -> {dst}", flush=True)
    try:
        packet_queue.put_nowait(packet_data)
    except queue.Full:
        pass

def packet_broadcaster():
    while True:
        try:
            packet_data = packet_queue.get(timeout=0.05)
            socketio.emit('packet_update', packet_data)
        except queue.Empty:
            time.sleep(0.01)
        except Exception as e:
            print(f"[Packet Broadcaster Error] {e}", flush=True)
            time.sleep(0.05)

def handle_security_alert(alert_data):
    print(f"[ALERT] {alert_data.get('title')}: {alert_data.get('details')}", flush=True)
    socketio.emit('security_alert', alert_data)

sniffer = NetworkSniffer(
    packet_callback=handle_new_packet,
    alert_data=handle_security_alert
)

def stats_broadcaster():
    while True:
        time.sleep(1.0)
        try:
            stats = sniffer.get_stats()
            socketio.emit('stats_update', stats)
        except Exception as e:
            print(f"[Stats Broadcaster Error] {e}", flush=True)

# Start background broadcaster threads
broadcaster_thread = threading.Thread(target=packet_broadcaster, daemon=True)
stats_thread = threading.Thread(target=stats_broadcaster, daemon=True)
broadcaster_thread.start()
stats_thread.start()

# Automatically start sniffer on default interface ('any')
sniffer.start('any')

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/status')
def get_status():
    return jsonify({
        "backend": "ONLINE",
        "scapy": "ACTIVE",
        "websocket": "CONNECTED",
        "capture": "RUNNING" if sniffer.is_capturing else "STOPPED",
        "interface": sniffer.selected_interface,
        "stats": sniffer.get_stats()
    })

@app.route('/api/interfaces')
def get_interfaces():
    return jsonify({
        "interfaces": sniffer.get_interfaces(),
        "selected": sniffer.selected_interface
    })

@app.route('/api/packets')
def get_packets():
    with sniffer.lock:
        pkts = list(sniffer.packets_history)
        stats = sniffer.get_stats()
    return jsonify({
        "status": stats["status"],
        "interface": stats["interface"],
        "total": stats["total"],
        "packets": pkts
    })

@app.route('/api/start', methods=['POST'])
def start_capture_rest():
    data = request.get_json(silent=True) or {}
    iface = data.get("interface", "any")
    success = sniffer.start(iface)
    socketio.emit('status_change', sniffer.get_stats())
    return jsonify({"success": success, "stats": sniffer.get_stats()})

@app.route('/api/stop', methods=['POST'])
def stop_capture_rest():
    sniffer.stop()
    socketio.emit('status_change', sniffer.get_stats())
    return jsonify({"success": True, "stats": sniffer.get_stats()})

@app.route('/api/clear', methods=['POST'])
def clear_packets_rest():
    sniffer.reset_stats()
    socketio.emit('clear_packets', {})
    socketio.emit('stats_update', sniffer.get_stats())
    return jsonify({"success": True})

@socketio.on('connect')
def handle_connect():
    print("[SOCKET] Client connected", flush=True)
    emit('init_state', {
        'stats': sniffer.get_stats(),
        'interfaces': sniffer.get_interfaces(),
        'selected_interface': sniffer.selected_interface,
        'packets': list(sniffer.packets_history)
    })

@socketio.on('disconnect')
def handle_disconnect():
    print("[SOCKET] Client disconnected", flush=True)

@socketio.on('start_capture')
def handle_start_capture(data):
    iface = data.get('interface', sniffer.selected_interface) if data else sniffer.selected_interface
    print(f"[CAPTURE] Starting capture on {iface}", flush=True)
    sniffer.start(iface)
    socketio.emit('status_change', sniffer.get_stats())

@socketio.on('stop_capture')
def handle_stop_capture():
    print("[CAPTURE] Stopping capture", flush=True)
    sniffer.stop()
    socketio.emit('status_change', sniffer.get_stats())

@socketio.on('clear_packets')
def handle_clear_packets():
    print("[CAPTURE] Clearing packet history", flush=True)
    sniffer.reset_stats()
    socketio.emit('clear_packets', {})
    socketio.emit('stats_update', sniffer.get_stats())

@socketio.on('change_interface')
def handle_change_interface(data):
    iface = data.get('interface') if data else 'any'
    if iface:
        print(f"[CAPTURE] Changing interface to {iface}", flush=True)
        sniffer.start(iface)
        socketio.emit('status_change', sniffer.get_stats())

if __name__ == '__main__':
    print("=================================================================", flush=True)
    print("        REAL-TIME NETWORK SECURITY MONITOR            ", flush=True)
    print("=================================================================", flush=True)
    print(f"Monitoring active on interface: {sniffer.selected_interface}", flush=True)
    print("Access Web Dashboard at: http://127.0.0.1:5000", flush=True)
    print("Press CTRL+C to stop.", flush=True)
    print("=================================================================", flush=True)
    socketio.run(app, host='0.0.0.0', port=5000, allow_unsafe_werkzeug=True)
