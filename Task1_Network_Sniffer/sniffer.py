import argparse
import csv
from datetime import datetime
from scapy.all import sniff, IP, IPv6, TCP, UDP, ICMP, DNS, Raw, get_if_list


def protocol_name(packet):
    if packet.haslayer(TCP):
        return "TCP"
    if packet.haslayer(UDP):
        return "UDP"
    if packet.haslayer(ICMP):
        return "ICMP"
    if packet.haslayer(DNS):
        return "DNS"
    if packet.haslayer(IP):
        return "IP"
    if packet.haslayer(IPv6):
        return "IPv6"
    return packet.lastlayer().name


def endpoints(packet):
    if packet.haslayer(IP):
        src, dst = packet[IP].src, packet[IP].dst
    elif packet.haslayer(IPv6):
        src, dst = packet[IPv6].src, packet[IPv6].dst
    else:
        return "-", "-"

    if packet.haslayer(TCP):
        src += f":{packet[TCP].sport}"
        dst += f":{packet[TCP].dport}"
    elif packet.haslayer(UDP):
        src += f":{packet[UDP].sport}"
        dst += f":{packet[UDP].dport}"
    return src, dst


def payload_preview(packet, limit=60):
    if not packet.haslayer(Raw):
        return "-"
    raw = bytes(packet[Raw].load)
    # Printable characters only; avoid dumping sensitive packet contents.
    text = "".join(chr(b) if 32 <= b <= 126 else "." for b in raw[:limit])
    return text


def packet_record(packet):
    src, dst = endpoints(packet)
    return {
        "time": datetime.now().isoformat(timespec="seconds"),
        "source": src,
        "destination": dst,
        "protocol": protocol_name(packet),
        "length": len(packet),
        "payload_preview": payload_preview(packet),
    }


def print_packet(packet, number):
    r = packet_record(packet)
    print(
        f"[{number:03}] {r['protocol']:<5} "
        f"{r['source']:<22} -> {r['destination']:<22} "
        f"len={r['length']:<5} payload={r['payload_preview']}"
    )


class Sniffer:
    def __init__(self, csv_file):
        self.number = 0
        self.rows = []
        self.csv_file = csv_file

    def handle(self, packet):
        self.number += 1
        print_packet(packet, self.number)
        self.rows.append(packet_record(packet))

    def save(self):
        if not self.rows:
            return
        with open(self.csv_file, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=self.rows[0].keys())
            writer.writeheader()
            writer.writerows(self.rows)
        print(f"\nSaved {len(self.rows)} packet summaries to {self.csv_file}")


def demo():
    print("DEMO MODE — no live network capture is performed.\n")
    examples = [
        ("TCP", "192.168.1.10:51544", "142.250.183.14:443", 128, "...."),
        ("UDP", "192.168.1.10:5353", "224.0.0.251:5353", 92, "....mDNS...."),
        ("ICMP", "192.168.1.10", "8.8.8.8", 84, "-"),
    ]
    for i, row in enumerate(examples, 1):
        print(f"[{i:03}] {row[0]:<5} {row[1]:<22} -> {row[2]:<22} len={row[3]:<5} payload={row[4]}")


def main():
    parser = argparse.ArgumentParser(description="CodeAlpha Basic Network Sniffer")
    parser.add_argument("--count", type=int, default=20, help="Number of packets to capture")
    parser.add_argument("--interface", help="Network interface to sniff on")
    parser.add_argument("--output", default="capture_summary.csv", help="CSV output filename")
    parser.add_argument("--demo", action="store_true", help="Run safe local demo instead of live capture")
    parser.add_argument("--list-interfaces", action="store_true", help="List available interfaces")
    args = parser.parse_args()

    if args.list_interfaces:
        print("\n".join(get_if_list()))
        return

    if args.demo:
        demo()
        return

    if args.count <= 0:
        parser.error("--count must be greater than 0")

    print("Starting network sniffer...")
    print("Use only on an authorized network/device. Press Ctrl+C to stop.\n")

    sniffer = Sniffer(args.output)
    try:
        sniff(
            iface=args.interface,
            prn=sniffer.handle,
            count=args.count,
            store=False,
        )
    except PermissionError:
        print("Permission denied. Run with the required capture privileges.")
    except KeyboardInterrupt:
        print("\nCapture stopped by user.")
    finally:
        sniffer.save()


if __name__ == "__main__":
    main()
