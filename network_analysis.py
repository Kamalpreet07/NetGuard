import pyshark
import pandas as pd


def analyze_pcap(file_path):

    capture = pyshark.FileCapture(
        file_path,
        keep_packets=False
    )

    packets = []

    protocol_count = {}
    source_count = {}
    destination_count = {}

    total_packets = 0
    total_bytes = 0

    for packet in capture:

        try:
            total_packets += 1

            protocol = packet.highest_layer

            protocol_count[protocol] = (
                protocol_count.get(protocol, 0) + 1
            )

            source = "Unknown"
            destination = "Unknown"

            if hasattr(packet, "ip"):
                source = packet.ip.src
                destination = packet.ip.dst

            elif hasattr(packet, "ipv6"):
                source = packet.ipv6.src
                destination = packet.ipv6.dst

            packet_size = int(packet.length)
            total_bytes += packet_size

            source_count[source] = (
                source_count.get(source, 0) + 1
            )

            destination_count[destination] = (
                destination_count.get(destination, 0) + 1
            )

            packets.append({
                "Protocol": protocol,
                "Source IP": source,
                "Destination IP": destination,
                "Packet Size (Bytes)": packet_size
            })

        except Exception:
            continue

    capture.close()

    dataframe = pd.DataFrame(packets)

    return {
        "total_packets": total_packets,
        "total_bytes": total_bytes,
        "protocol_count": protocol_count,
        "source_count": source_count,
        "destination_count": destination_count,
        "dataframe": dataframe
    }
