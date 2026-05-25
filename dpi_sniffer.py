import sys
from datetime import datetime
from scapy.all import sniff, Raw
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.dns import DNS, DNSQR


KEYWORDS = [b"user", b"password", b"pass", b"login", b"email", b"secret"]

INSECURE_PORTS = {
    21: "FTP",
    23: "Telnet",
    80: "HTTP",
    110: "POP3",
    143: "IMAP"
}


def get_timestamp():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def parse_payload(packet):
    if packet.haslayer(Raw):
        raw_payload = bytes(packet[Raw].load)

        for keyword in KEYWORDS:
            if keyword in raw_payload.lower():
                decoded = raw_payload.decode("utf-8", errors="ignore").strip()
                return f"[⚠️ POSSIBLE PLAINTEXT DATA LEAK]: {decoded[:120]}"

    return None


def parse_tcp(packet):
    src_ip = packet[IP].src
    dst_ip = packet[IP].dst
    src_port = packet[TCP].sport
    dst_port = packet[TCP].dport
    flags = packet[TCP].flags
    length = len(packet)

    output = (
        f"[{get_timestamp()}] [TCP]\n"
        f"  Source: {src_ip}:{src_port}\n"
        f"  Destination: {dst_ip}:{dst_port}\n"
        f"  Flags: {flags}\n"
        f"  Packet Length: {length} bytes"
    )

    if src_port in INSECURE_PORTS or dst_port in INSECURE_PORTS:
        service = INSECURE_PORTS.get(src_port) or INSECURE_PORTS.get(dst_port)
        output += f"\n  [⚠️ INSECURE PROTOCOL DETECTED]: {service}"

    leak = parse_payload(packet)
    if leak:
        output += f"\n  {leak}"

    return output


def parse_udp(packet):
    src_ip = packet[IP].src
    dst_ip = packet[IP].dst
    src_port = packet[UDP].sport
    dst_port = packet[UDP].dport
    length = len(packet)

    output = (
        f"[{get_timestamp()}] [UDP]\n"
        f"  Source: {src_ip}:{src_port}\n"
        f"  Destination: {dst_ip}:{dst_port}\n"
        f"  Packet Length: {length} bytes"
    )

    if packet.haslayer(DNS) and packet.haslayer(DNSQR):
        query = packet[DNSQR].qname.decode("utf-8", errors="ignore")
        output += f"\n  DNS Query: {query}"

    return output


def parse_icmp(packet):
    src_ip = packet[IP].src
    dst_ip = packet[IP].dst
    icmp_type = packet[ICMP].type
    icmp_code = packet[ICMP].code
    length = len(packet)

    return (
        f"[{get_timestamp()}] [ICMP]\n"
        f"  Source: {src_ip}\n"
        f"  Destination: {dst_ip}\n"
        f"  Type: {icmp_type}\n"
        f"  Code: {icmp_code}\n"
        f"  Packet Length: {length} bytes"
    )


def handle_packet(packet, log):
    if not packet.haslayer(IP):
        return

    output = None

    if packet.haslayer(TCP):
        output = parse_tcp(packet)

    elif packet.haslayer(UDP):
        output = parse_udp(packet)

    elif packet.haslayer(ICMP):
        output = parse_icmp(packet)

    if output:
        print(output)
        print("-" * 60)
        log.write(output + "\n" + "-" * 60 + "\n")


def main(interface):
    logfile_name = "portfolio_sniffer_log.txt"

    print("=" * 60)
    print("[*] LAUNCHING PORTFOLIO PACKET SNIFFER")
    print(f"[*] Target Interface: {interface}")
    print("[*] BPF Filter: IP traffic only")
    print("[*] Protocol Parsing: TCP / UDP / ICMP / DNS")
    print("[*] Security Detection: Plaintext leaks + insecure protocols")
    print("=" * 60)

    with open(logfile_name, "a", encoding="utf-8") as logfile:
        try:
                sniff(
                iface=interface,
                filter="icmp",
                prn=lambda pkt: handle_packet(pkt, logfile),
                store=0
            )

        except KeyboardInterrupt:
            print("\n[*] Shutting down sniffer cleanly.")
            print(f"[*] Logs saved to: {logfile_name}")
            sys.exit(0)


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python sniffer.py <interface_name>")
        sys.exit(1)

    main(sys.argv[1])
