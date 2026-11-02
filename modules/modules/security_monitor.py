
from collections import Counter, defaultdict, deque
from datetime import datetime, timedelta
import threading


class SecurityMonitor:

    def __init__(
        self,
        port_scan_threshold=15,
        connection_threshold=30,
        traffic_threshold=10 * 1024 * 1024
    ):
        self.port_scan_threshold = port_scan_threshold
        self.connection_threshold = connection_threshold
        self.traffic_threshold = traffic_threshold

        self.alerts = deque(maxlen=500)

        self.source_ports = defaultdict(set)
        self.source_destinations = defaultdict(Counter)
        self.source_bytes = Counter()

        self.connection_events = defaultdict(deque)
        self.lock = threading.Lock()

        self.alert_keys = {}

    def _add_alert(self, severity, alert_type, source, message):
        now = datetime.now()

        key = (alert_type, source)
        previous = self.alert_keys.get(key)

        if previous and now - previous < timedelta(seconds=60):
            return

        self.alert_keys[key] = now

        self.alerts.append({
            "time": now.strftime("%Y-%m-%d %H:%M:%S"),
            "severity": severity,
            "type": alert_type,
            "source": source,
            "message": message
        })

    def analyze_packet(self, packet_info):
        source = packet_info.get("source")
        destination = packet_info.get("destination")

        if not source or not destination:
            return

        if source == "Unknown" or destination == "Unknown":
            return

        try:
            size = int(packet_info.get("size", 0))
        except (ValueError, TypeError):
            size = 0

        now = datetime.now()

        with self.lock:

            self.source_destinations[source][destination] += 1
            self.source_bytes[source] += size

            # Check for repeated connections.
            events = self.connection_events[source]
            events.append(now)

            while events and now - events[0] > timedelta(seconds=60):
                events.popleft()

            if len(events) >= self.connection_threshold:
                self._add_alert(
                    "Medium",
                    "Repeated Network Activity",
                    source,
                    "Many packets from this source within one minute."
                )

            # Check destination ports when available.
            destination_port = None

            try:
                if packet_info.get("destination_port") is not None:
                    destination_port = int(
                        packet_info["destination_port"]
                    )
            except (ValueError, TypeError):
                pass

            if destination_port is not None:
                ports = self.source_ports[source]
                ports.add(destination_port)

                if len(ports) >= self.port_scan_threshold:
                    self._add_alert(
                        "High",
                        "Possible Port Scan",
                        source,
                        "This source contacted many different destination ports."
                    )

            # Check unusually high traffic volume.
            if self.source_bytes[source] >= self.traffic_threshold:
                self._add_alert(
                    "Medium",
                    "High Traffic Volume",
                    source,
                    "This source transferred a large amount of data."
                )

    def get_alerts(self):
        with self.lock:
            return list(reversed(self.alerts))

    def get_summary(self):
        with self.lock:
            alerts = list(self.alerts)

            return {
                "total_alerts": len(alerts),
                "high": sum(
                    1 for alert in alerts
                    if alert["severity"] == "High"
                ),
                "medium": sum(
                    1 for alert in alerts
                    if alert["severity"] == "Medium"
                ),
                "low": sum(
                    1 for alert in alerts
                    if alert["severity"] == "Low"
                ),
                "recent_alerts": list(reversed(alerts[-10:]))
            }

    def clear_alerts(self):
        with self.lock:
            self.alerts.clear()
            self.alert_keys.clear()
            self.source_ports.clear()
            self.source_destinations.clear()
            self.source_bytes.clear()
            self.connection_events.clear()
