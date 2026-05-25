# High-Performance Deep Packet Inspection (DPI) Sniffer

A portfolio-grade network analysis tool built in Python using Scapy, engineered to intercept local network traffic, parse multiple layer protocols, and identify unencrypted credential or PII leaks in real-time.

## Key Highlights & Architecture

* **Hybrid Architecture Performance:** Utilizes a Python-driven Scapy implementation backed by the native C/C++ Npcap library. This allows low-level packet capture to happen directly at the Windows kernel network driver layer, maximizing execution efficiency and minimizing packet drops.
* **Kernel-Level Filtering:** Leverages Berkeley Packet Filters (BPF) (`filter="ip"`) to offload packet processing to the operating system kernel, drastically reducing CPU overhead.
* **Deep Packet Inspection (DPI):** Features targeted payload parsing across unencrypted application layers (HTTP) to identify plaintext exposures of credentials or private identifiers (`user`, `password`, `email`).
* **Multi-Protocol Suite:** Dynamically dissects network packets across standard networking protocols including TCP, UDP, and ICMP control mappings.

## Installation & Setup

### Prerequisites
* Windows 10/11
* Python 3.x
* [Npcap Driver Package](https://npcap.com/) (Required for Windows raw socket hook)

### Dependencies
Install the required network manipulation library:
```bash
pip install scapy

## Architecture

Packet Capture Layer
↓
Packet Parsing
↓
Protocol Identification
↓
Filtering
↓
Output / Logging

## Features

- Packet capture
- Protocol identification
- Source / destination IP extraction
- Traffic visibility
- Packet filtering
