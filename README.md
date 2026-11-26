
# Basic Network Sniffer

A Python-based network packet analyser that captures packet metadata and generates CSV reports.

## Features

- Capture up to 10 IP packets
- Identify TCP, UDP and ICMP protocols
- Display source and destination IP addresses
- Display source and destination port numbers
- Display packet timestamps
- Generate CSV reports
- Display protocol statistics

## Technologies Used

- Python
- Scapy
- CSV
- Npcap
- VS Code

## Requirements

- Python 3
- Scapy
- Npcap (Windows)

## Installation

Install Scapy:

```bash
py -m pip install scapy
```

Install Npcap on Windows if required.

## How to Run

Open the project folder in VS Code.

Run the terminal as administrator if required for authorised packet capture.

Execute:

```bash
py network_sniffer.py
```

The program captures up to 10 packets and generates:

`packet_report.csv`

## Security Notice

Use this tool only on your own device or networks where you have explicit permission. Packet reports may contain sensitive network metadata.

## Author

**MAGUDESWARAN S**

Cyber Security Intern
CodeAlpha Internship Program
