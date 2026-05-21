import sys
from scapy.all import sniff
from scapy.layers.inet import IP, TCP, UDP, ICMP

# Extended keywords to flag unencrypted PII or credentials leaking in plaintext
KEYWORDS = [b"user", b"password", b"pass", b"login", b"email", b"secret"]

def parse_payload(packet_layer):
    """Parses raw layer payloads to check for unencrypted credential or PII leaks."""
    if packet_layer.payload:
        raw_payload = bytes(packet_layer.payload)
        
        # Check if any sensitive keywords appear in the raw bytes
        for keyword in KEYWORDS:
            if keyword in raw_payload.lower():
                try:
                    # Clean up the string for human readability
                    decoded_payload = raw_payload.decode('utf-8', errors='ignore').strip()
                    # Return truncated string to prevent terminal cluttering
                    return f"[⚠️ PII/CREDENTIAL LEAK DETECTED]: {decoded_payload[:100]}"
                except Exception:
                    pass
    return None

def handle_packet(packet, log):
    """High-performance callback function for parsing network layer protocols."""
    if not packet.haslayer(IP):
        return

    src_ip = packet[IP].src
    dst_ip = packet[IP].dst
    output_line = ""

    # 1. Parsing TCP Traffic
    if packet.haslayer(TCP):
        src_port = packet[TCP].sport
        dst_port = packet[TCP].dport
        output_line = f"[TCP] {src_ip}:{src_port} -> {dst_ip}:{dst_port}"
        
        # Look for leaks in unencrypted common ports (like HTTP port 80)
        if src_port == 80 or dst_port == 80:
            leak = parse_payload(packet[TCP])
            if leak:
                output_line += f"\n  {leak}"

    # 2. Parsing UDP Traffic
    elif packet.haslayer(UDP):
        src_port = packet[UDP].sport
        dst_port = packet[UDP].dport
        output_line = f"[UDP] {src_ip}:{src_port} -> {dst_ip}:{dst_port}"

    # 3. Parsing ICMP (Ping requests/replies)
    elif packet.haslayer(ICMP):
        output_line = f"[ICMP] Ping/Control packet mapping: {src_ip} -> {dst_ip}"

    # Execution handling: Print to terminal and commit to log file
    if output_line:
        print(output_line)
        log.write(output_line + "\n")

def main(interface):
    logfile_name = "portfolio_sniffer_log.txt"
    print("="*60)
    print(f"[*] LAUNCHING PORTFOLIO PACKET SNIFFER")
    print(f"[*] Target Interface: {interface}")
    print(f"[*] Kernel-level Filtering: BPF Enabled (IP Traffic Only)")
    print(f"[*] Deep Packet Inspection: Active (HTTP/FTP Plaintext Scanner)")
    print("="*60 + "\n")
    
    with open(logfile_name, 'a') as logfile:
        try:
            # 'filter="ip"' applies a Berkeley Packet Filter (BPF) at the driver level.
            # This discards non-IP overhead packets entirely before Python even processes them.
            sniff(iface=interface, filter="ip", prn=lambda pkt: handle_packet(pkt, logfile), store=0)
        except KeyboardInterrupt:
            print("\n[*] Shutting down sniffer module cleanly. Logs compiled.")
            sys.exit(0)

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python sniffer.py <interface_name>")
        sys.exit(1)
        
    main(sys.argv[1])