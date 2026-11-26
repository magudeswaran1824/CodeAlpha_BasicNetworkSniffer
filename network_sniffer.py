
from collections import Counter
import csv
from datetime import datetime
from scapy.all import IP, TCP, UDP, ICMP, sniff

packets_data = []


def analyse_packet(packet):

    if IP not in packet:
        return

    ip = packet[IP]

    source = ip.src
    destination = ip.dst
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    protocol = "Other"
    source_port = "-"
    destination_port = "-"

    if TCP in packet:
        protocol = "TCP"
        source_port = packet[TCP].sport
        destination_port = packet[TCP].dport

    elif UDP in packet:
        protocol = "UDP"
        source_port = packet[UDP].sport
        destination_port = packet[UDP].dport

    elif ICMP in packet:
        protocol = "ICMP"

    data = {
        "Timestamp": timestamp,
        "Source IP": source,
        "Destination IP": destination,
        "Protocol": protocol,
        "Source Port": source_port,
        "Destination Port": destination_port
    }

    packets_data.append(data)

    print("\n========== PACKET DETAILS ==========")

    for key, value in data.items():
        print(f"{key}: {value}")

print("====================================")
print("       BASIC NETWORK SNIFFER")
print("====================================")

print("\nCapturing 10 packets...")
print("Use only your own device or an authorised network.")


sniff(
    filter="ip",
    prn=analyse_packet,
    count=10,
    store=False
)

if packets_data:


    with open(
        "packet_report.csv",
        "w",
        newline="",
        encoding="utf-8"
    ) as file:

        writer = csv.DictWriter(
            file,
            fieldnames=packets_data[0].keys()
        )

        writer.writeheader()
        writer.writerows(packets_data)

    print("\nReport saved: packet_report.csv")

    protocol_counts = Counter(
        item["Protocol"] for item in packets_data
    )

    print("\n========== PROTOCOL SUMMARY ==========")

    for protocol, total in sorted(protocol_counts.items()):
        print(f"{protocol}: {total} packets")

    print("--------------------------------------")
    print("Total Packets:", len(packets_data))
    print("======================================")

else:
    print("\nNo packets captured.")
