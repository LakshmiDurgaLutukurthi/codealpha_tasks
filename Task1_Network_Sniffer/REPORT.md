# CodeAlpha Cyber Security Internship — Task 1
## Basic Network Sniffer

### 1. Objective
The objective is to build a Python program that captures network traffic packets and analyzes basic packet information such as source IP, destination IP, protocol, ports, packet length, and a limited payload preview.

This follows the CodeAlpha task instructions, which specifically request a Python packet-capture program and mention Scapy or socket. The program also demonstrates basic protocol structure and network data flow.

### 2. Technologies
- Python
- Scapy
- CSV
- Command-line interface

### 3. Working
1. The program starts Scapy's packet capture function.
2. Each captured packet is passed to a callback.
3. The callback identifies IPv4/IPv6 addresses.
4. TCP/UDP source and destination ports are displayed when available.
5. The protocol is identified.
6. A short printable payload preview is generated when a Raw layer exists.
7. A summary is written to `capture_summary.csv`.

### 4. Example
```text
[001] TCP   192.168.1.10:51544 -> 142.250.183.14:443 len=128 payload=....
[002] UDP   192.168.1.10:5353  -> 224.0.0.251:5353 len=92 payload=....mDNS....
[003] ICMP  192.168.1.10       -> 8.8.8.8              len=84 payload=-
```

### 5. Security and Ethics
Packet capture can expose sensitive information. This project must only be used on systems and networks for which the user has permission. The payload display is intentionally limited and sanitized rather than dumping complete packet contents.

### 6. Testing
Use demo mode first:
```bash
python sniffer.py --demo
```

Then list interfaces:
```bash
python sniffer.py --list-interfaces
```

Finally perform a small authorized capture:
```bash
python sniffer.py --count 10
```

### 7. Conclusion
The project provides practical exposure to packet capture, protocol identification, network endpoints, and basic packet analysis. It can be extended with filtering, protocol statistics, PCAP export, and visualization.

### 8. CodeAlpha submission checklist
According to the supplied instructions:
- Complete the assigned project within the required time.
- Upload source code to GitHub using the repository naming pattern `CodeAlpha_ProjectName`.
- Post a video explanation on LinkedIn with the GitHub repository link.
- Submit the completed task through the provided submission form.
- The supplied document states that a minimum of two or three tasks must be completed for internship certificate eligibility.
