# CodeAlpha Task 1 — Basic Network Sniffer

A beginner-friendly Python network packet sniffer built with Scapy.

## Internship task
CodeAlpha's Cyber Security task list asks interns to build a Python program that captures network traffic, analyzes packet structure, and displays source/destination IPs, protocols, and payloads. The instructions mention Scapy or socket. 

## Features
- Captures packets with Scapy
- Displays source/destination IP addresses
- Detects common protocols
- Shows ports when available
- Shows a safe, truncated payload preview
- Configurable packet count and interface
- Saves captured packet summary to CSV
- Includes a local demo mode for testing without live capture

## Requirements
- Python 3.9+
- Scapy

Install:
```bash
pip install -r requirements.txt
```

## Run
Windows may require Npcap for live packet capture.

```bash
python sniffer.py --count 20
```

List interfaces:
```bash
python sniffer.py --list-interfaces
```

Capture on a specific interface:
```bash
python sniffer.py --interface "Wi-Fi" --count 20
```

Demo mode (no live capture):
```bash
python sniffer.py --demo
```

## Ethical use
Use this project only on networks/devices you own or are explicitly authorized to monitor. Do not capture or inspect other people's traffic.

## Project structure
- `sniffer.py` — main program
- `requirements.txt` — dependency
- `README.md` — setup and usage
- `REPORT.md` — internship report
- `sample_output.txt` — example output
- `.gitignore` — Git exclusions
