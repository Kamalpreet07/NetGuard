
import pyshark
import pandas as pd
from collections import Counter


def analyze_pcap(file_path):

    protocols = Counter()
    source_ips = Counter()
    destination_ips = Counter()
    destination_ports = Counter()
    packet_sizes = []

    packet_details = []

    total_packets = 0
    total_bytes = 0

    try:
        capture = pyshark.FileCapture(
            file_path,
            keep_packets=False
        )

        try:
            for packet in capture:

                try:
                    total_packets += 1

                    packet_size = int(packet.length)
                    total_bytes += packet_size
                    packet_sizes.append(packet_size)

                    protocol = packet.highest_layer
                    protocols[protocol] += 1

                    source = "Unknown"
                    destination = "Unknown"

                    if hasattr(packet, "ip"):
                        source = packet.ip.src
                        destination = packet.ip.dst

                    elif hasattr(packet, "ipv6"):
                        source = packet.ipv6.src
                        destination = packet.ipv6.dst

                    source_ips[source] += 1
                    destination_ips[destination] += 1

                    source_port = None
                    destination_port = None

                    if hasattr(packet, "tcp"):
                        source_port = packet.tcp.srcport
                        destination_port = packet.tcp.dstport

                    elif hasattr(packet, "udp"):
                        source_port = packet.udp.srcport
                        destination_port = packet.udp.dstport

                    if destination_port is not None:
                        destination_ports[str(destination_port)] += 1

                    timestamp = getattr(
                        packet,
                        "sniff_time",
                        None
                    )

                    packet_details.append({
                        "Packet Number": total_packets,
                        "Time": str(timestamp) if timestamp else "Unknown",
                        "Protocol": protocol,
                        "Source IP": source,
                        "Destination IP": destination,
                        "Source Port": source_port,
                        "Destination Port": destination_port,
                        "Packet Size (Bytes)": packet_size
                    })

                except Exception:
                    continue

        finally:
            capture.close()

        dataframe = pd.DataFrame(packet_details)

        protocol_dataframe = pd.DataFrame(
            [
                {"Protocol": name, "Packets": count}
                for name, count in protocols.most_common()
            ]
        )

        source_dataframe = pd.DataFrame(
            [
                {"Source IP": ip, "Packets": count}
                for ip, count in source_ips.most_common(10)
            ]
        )

        destination_dataframe = pd.DataFrame(
            [
                {"Destination IP": ip, "Packets": count}
                for ip, count in destination_ips.most_common(10)
            ]
        )

        port_dataframe = pd.DataFrame(
            [
                {"Destination Port": port, "Packets": count}
                for port, count in destination_ports.most_common(10)
            ]
        )

        if not dataframe.empty:
            dataframe["Time"] = pd.to_datetime(
                dataframe["Time"],
                errors="coerce"
            )

            traffic_timeline = (
                dataframe.dropna(subset=["Time"])
                .set_index("Time")
                .resample("1s")
                .agg({
                    "Packet Number": "count",
                    "Packet Size (Bytes)": "sum"
                })
                .reset_index()
            )
        else:
            traffic_timeline = pd.DataFrame(
                columns=[
                    "Time",
                    "Packet Number",
                    "Packet Size (Bytes)"
                ]
            )

        return {
            "success": True,
            "total_packets": total_packets,
            "total_bytes": total_bytes,
            "protocol_count": dict(protocols),
            "source_count": dict(source_ips),
            "destination_count": dict(destination_ips),
            "destination_ports": dict(destination_ports),
            "top_protocols": protocol_dataframe,
            "top_sources": source_dataframe,
            "top_destinations": destination_dataframe,
            "top_ports": port_dataframe,
            "packet_sizes": packet_sizes,
            "traffic_timeline": traffic_timeline,
            "dataframe": dataframe,
            "error": None
        }

    except Exception as error:

        return {
            "success": False,
            "total_packets": 0,
            "total_bytes": 0,
            "protocol_count": {},
            "source_count": {},
            "destination_count": {},
            "destination_ports": {},
            "top_protocols": pd.DataFrame(),
            "top_sources": pd.DataFrame(),
            "top_destinations": pd.DataFrame(),
            "top_ports": pd.DataFrame(),
            "packet_sizes": [],
            "traffic_timeline": pd.DataFrame(),
            "dataframe": pd.DataFrame(),
            "error": str(error)
        }
