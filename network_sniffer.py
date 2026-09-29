import time
import threading
from collections import deque
from scapy.all import AsyncSniffer, get_if_list, IP, TCP, UDP, ICMP, conf

class NetworkSniffer:
    def __init__(self, packet_callback=None, alert_data=None):
        self.packet_callback = packet_callback
        self.alert_callback = alert_data
        self.is_capturing = False
        self.lock = threading.Lock()
        self.packets_history = deque(maxlen=1000)
        self.sniffer_instance = None
        self.selected_interface = "any"
        
        self.total_packets = 0
        self.tcp_count = 0
        self.udp_count = 0
        self.icmp_count = 0
        self.other_count = 0
        self.total_bytes = 0
        
        self.recent_packet_timestamps = deque(maxlen=100)
        self.port_scan_tracker = {}
        self.last_alert_time = 0

    def get_interfaces(self):
        try:
            ifaces = get_if_list()
            if ifaces:
                res = list(set(ifaces))
                if "any" not in res:
                    res.insert(0, "any")
                return res
        except Exception:
            pass
        return ['any', 'eth0', 'lo', 'wlan0']

    def get_default_interface(self):
        return "any"

    def start(self, interface=None):
        with self.lock:
            if self.is_capturing:
                self._stop_internal()

            if interface:
                self.selected_interface = interface
            else:
                self.selected_interface = "any"

            try:
                target_iface = None if (self.selected_interface == 'any' or not self.selected_interface) else self.selected_interface
                self.sniffer_instance = AsyncSniffer(
                    iface=target_iface,
                    prn=self._process_packet,
                    store=False
                )
                self.sniffer_instance.start()
                self.is_capturing = True
                print(f"[SNIFFER] Started capturing on {self.selected_interface}", flush=True)
                return True
            except Exception as e:
                print(f"[SNIFFER ERROR] Failed to start sniffer on {self.selected_interface}: {e}", flush=True)
                self.is_capturing = False
                return False

    def _stop_internal(self):
        if self.sniffer_instance:
            try:
                self.sniffer_instance.stop()
            except Exception as e:
                print(f"[SNIFFER ERROR] Stopping sniffer error: {e}", flush=True)
            self.sniffer_instance = None
        self.is_capturing = False

    def stop(self):
        with self.lock:
            self._stop_internal()
            print("[SNIFFER] Stopped packet capture", flush=True)

    def reset_stats(self):
        with self.lock:
            self.total_packets = 0
            self.tcp_count = 0
            self.udp_count = 0
            self.icmp_count = 0
            self.other_count = 0
            self.total_bytes = 0
            self.packets_history.clear()
            self.recent_packet_timestamps.clear()
            self.port_scan_tracker.clear()

    def get_stats(self):
        with self.lock:
            now = time.time()
            recent = [t for t in self.recent_packet_timestamps if now - t <= 2.0]
            pps = len(recent) / 2.0 if recent else 0

            return {
                "status": "RUNNING" if self.is_capturing else "STOPPED",
                "interface": self.selected_interface,
                "total": self.total_packets,
                "tcp": self.tcp_count,
                "udp": self.udp_count,
                "icmp": self.icmp_count,
                "other": self.other_count,
                "total_bytes": self.total_bytes,
                "pps": round(pps, 1)
            }

    def _process_packet(self, packet):
        if IP not in packet:
            return

        now = time.time()
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        pkt_size = len(bytes(packet))
        
        proto = "Other"
        src_port = "-"
        dst_port = "-"

        if TCP in packet:
            proto = "TCP"
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
        elif UDP in packet:
            proto = "UDP"
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport
        elif ICMP in packet:
            proto = "ICMP"

        packet_data = {
            "id": self.total_packets + 1,
            "timestamp": time.strftime("%H:%M:%S", time.localtime(now)),
            "source_ip": src_ip,
            "destination_ip": dst_ip,
            "protocol": proto,
            "source_port": src_port,
            "destination_port": dst_port,
            "payload_size": pkt_size
        }

        with self.lock:
            self.total_packets += 1
            self.total_bytes += pkt_size
            self.recent_packet_timestamps.append(now)

            if proto == "TCP":
                self.tcp_count += 1
            elif proto == "UDP":
                self.udp_count += 1
            elif proto == "ICMP":
                self.icmp_count += 1
            else:
                self.other_count += 1

            self.packets_history.append(packet_data)

            recent_count = len([t for t in self.recent_packet_timestamps if now - t <= 1.0])
            if recent_count > 60 and (now - self.last_alert_time > 5):
                self.last_alert_time = now
                if self.alert_callback:
                    self.alert_callback({
                        "title": "TRAFFIC SPIKE DETECTED",
                        "level": "HIGH",
                        "details": f"High rate burst: {recent_count} pkts/sec on {self.selected_interface}",
                        "timestamp": packet_data["timestamp"]
                    })

            if dst_port != "-":
                tracker_key = (src_ip, dst_ip)
                if tracker_key not in self.port_scan_tracker:
                    self.port_scan_tracker[tracker_key] = set()
                self.port_scan_tracker[tracker_key].add(dst_port)
                
                if len(self.port_scan_tracker[tracker_key]) >= 15 and (now - self.last_alert_time > 5):
                    self.last_alert_time = now
                    if self.alert_callback:
                        self.alert_callback({
                            "title": "POTENTIAL PORT SCAN DETECTED",
                            "level": "WARNING",
                            "details": f"Source {src_ip} probed {len(self.port_scan_tracker[tracker_key])} ports on {dst_ip}",
                            "timestamp": packet_data["timestamp"]
                        })

        if self.packet_callback:
            try:
                self.packet_callback(packet_data)
            except Exception as e:
                print(f"[PACKET CALLBACK ERROR] {e}", flush=True)
