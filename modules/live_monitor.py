
import subprocess
import threading
import time
from collections import Counter, deque
from datetime import datetime

import pyshark


class LiveNetworkMonitor:

    def __init__(self):
        self.running = False
        self.capture = None
        self.thread = None

        self.lock = threading.Lock()

        self.total_packets = 0
        self.total_bytes = 0
        self.protocols = Counter()
        self.source_ips = Counter()
        self.destination_ips = Counter()

        self.packet_history = deque(maxlen=100)
        self.traffic_history = deque(maxlen=60)

        self.start_time = None
        self.error = None

    def get_interfaces(self):
        try:
            result = subprocess.run(
                ["tshark", "-D"],
                capture_output=True,
                text=True,
                timeout=10
            )

            if result.returncode != 0:
                self.error = result.stderr.strip()
                return []

            interfaces = []

            for line in result.stdout.splitlines():
                parts = line.split(".", 1)

                if len(parts) == 2:
                    interfaces.append(parts[1].strip())

            return interfaces

        except Exception as error:
            self.error = str(error)
            return []

    def start_monitoring(self, interface):
        if self.running:
            return False

        self.total_packets = 0
        self.total_bytes = 0
        self.protocols.clear()
        self.source_ips.clear()
        self.destination_ips.clear()
        self.packet_history.clear()
        self.traffic_history.clear()
        self.error = None

        self.start_time = datetime.now()
        self.running = True

        self.thread = threading.Thread(
            target=self._capture_packets,
            args=(interface,),
            daemon=True
        )

        self.thread.start()
        return True

    def _capture_packets(self, interface):
        try:
            self.capture = pyshark.LiveCapture(
                interface=interface
            )

            for packet in self.capture.sniff_continuously():

                if not self.running:
                    break

                try:
                    packet_size = int(packet.length)
                    protocol = packet.highest_layer

                    source = "Unknown"
                    destination = "Unknown"

                    if hasattr(packet, "ip"):
                        source = packet.ip.src
                        destination = packet.ip.dst

                    elif hasattr(packet, "ipv6"):
                        source = packet.ipv6.src
                        destination = packet.ipv6.dst

                    packet_info = {
                        "time": datetime.now().strftime("%H:%M:%S"),
                        "protocol": protocol,
                        "source": source,
                        "destination": destination,
                        "size": packet_size
                    }

                    with self.lock:
                        self.total_packets += 1
                        self.total_bytes += packet_size

                        self.protocols[protocol] += 1

                        if source != "Unknown":
                            self.source_ips[source] += 1

                        if destination != "Unknown":
                            self.destination_ips[destination] += 1

                        self.packet_history.append(packet_info)

                        self.traffic_history.append({
                            "time": packet_info["time"],
                            "bytes": packet_size
                        })

                except Exception:
                    continue

        except Exception as error:
            self.error = str(error)

        finally:
            self.running = False

    def stop_monitoring(self):
        self.running = False

        if self.capture:
            try:
                self.capture.close()
            except Exception:
                pass

        return True

    def get_statistics(self):
        with self.lock:
            return {
                "running": self.running,
                "total_packets": self.total_packets,
                "total_bytes": self.total_bytes,
                "protocols": dict(self.protocols),
                "source_ips": dict(self.source_ips.most_common(10)),
                "destination_ips": dict(
                    self.destination_ips.most_common(10)
                ),
                "recent_packets": list(self.packet_history),
                "traffic_history": list(self.traffic_history),
                "start_time": (
                    self.start_time.strftime("%Y-%m-%d %H:%M:%S")
                    if self.start_time else None
                ),
                "error": self.error
            }
