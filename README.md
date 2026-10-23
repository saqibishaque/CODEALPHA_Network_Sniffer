# CodeAlpha — Basic Network Sniffer

A lightweight, modular Python program designed to capture, parse, and analyze real-time network packets across interfaces. Developed as part of the **CodeAlpha Cyber Security Internship** (Task 1).

---

## 🎯 Project Features
- **Live Packet Capture**: Captures incoming and outgoing network traffic in real time.
- **Protocol Dissection**: Automatically parses IPv4, TCP, UDP, ICMP, and ARP headers.
- **Port & Address Resolution**: Displays Source & Destination IP addresses alongside respective transport ports and TCP flags.
- **Payload Inspection**: Safely decodes raw data payloads into readable ASCII format for packet inspection.
- **Filtering Support**: Leverages Berkeley Packet Filters (BPF) to narrow down capture traffic (e.g., `tcp`, `udp`, `port 80`, `icmp`).
- **Session Logging**: Option to export captured packets into a timestamped text log file.

---

## 🛠️ Prerequisites & Installation

### 1. Requirements
- Python 3.8 or above
- **Windows Users**: Must have [Npcap](https://npcap.com/#download) installed with **"Install Npcap in WinPcap API-compatible Mode"** checked.
- **Linux Users**: Ensure `libpcap` is installed (`sudo apt install libpcap-dev`).

### 2. Install Python Dependencies
```bash
pip install -r requirements.txt
```

---

## 🚀 Usage Guide

> ⚠️ **Important:** Packet capturing operates at the data-link/network layer and requires **Administrator** (Windows) or **Root** (Linux/macOS) privileges. Always launch your terminal as Administrator.

### 1. Basic Sniffing (All Traffic)
```bash
python sniffer.py
```

### 2. Capture a Specific Number of Packets
Capture 10 packets and exit:
```bash
python sniffer.py -c 10
```

### 3. Filter by Protocol or Port
Filter only TCP packets:
```bash
python sniffer.py -f "tcp"
```

Filter web HTTP/HTTPS traffic:
```bash
python sniffer.py -f "tcp port 80 or tcp port 443"
```

Filter ICMP (Ping) traffic:
```bash
python sniffer.py -f "icmp"
```

### 4. Save Captured Traffic to a Log File
```bash
python sniffer.py -f "tcp" -o traffic_log.txt
```

### 5. Command-Line Options
| Argument | Description | Default |
| :--- | :--- | :--- |
| `-i`, `--interface` | Network interface to sniff on | System default |
| `-c`, `--count` | Number of packets to capture | 0 (Infinite) |
| `-f`, `--filter` | BPF filter string | None |
| `-o`, `--output` | Destination file for text log | None |
| `--no-payload` | Omit raw payload preview | False |

---

## 📸 Sample Output
```text
====================================================
      CodeAlpha - Basic Network Packet Sniffer      
====================================================
Interface : Default
Filter    : tcp
Count     : Infinite
Log File  : Disabled
Press Ctrl+C at any time to stop capturing...

[2026-10-23 17:45:00] TCP   | 192.168.1.15:52341 -> 142.250.190.46:443 | Flags: [PA]
   └─ Payload Preview: .....X...`..... ... [517 bytes total]
[2026-10-23 17:45:01] TCP   | 142.250.190.46:443 -> 192.168.1.15:52341 | Flags: [A]
```

---

## 🔒 Ethical Disclaimer
This project is built strictly for **educational and defensive cybersecurity analysis**. Capturing traffic on networks without authorization is illegal. Only run this tool on networks and machines you own or have explicit permission to monitor.
