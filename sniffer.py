import argparse
import sys
from datetime import datetime
from scapy.all import sniff, IP, TCP, UDP, ICMP, ARP, Raw, conf

# ANSI terminal colors for formatted output
class Colors:
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'

def format_payload(raw_data, max_len=64):
    """Safely decode and format raw packet payload into printable ASCII."""
    try:
        # Convert bytes to printable characters, replace unprintable with '.'
        payload_str = "".join([chr(b) if 32 <= b <= 126 else "." for b in raw_data[:max_len]])
        if len(raw_data) > max_len:
            payload_str += f" ... [{len(raw_data)} bytes total]"
        return payload_str
    except Exception:
        return "[Non-printable payload data]"

def packet_callback(packet, show_payload=True, log_file=None):
    """Callback triggered whenever a packet is captured."""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # Handle IP Packets
    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        protocol = "OTHER"
        src_port = "-"
        dst_port = "-"
        info = ""

        if TCP in packet:
            protocol = "TCP"
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
            flags = packet[TCP].flags
            info = f"Flags: [{flags}]"
        elif UDP in packet:
            protocol = "UDP"
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport
            info = f"Length: {packet[UDP].len}"
        elif ICMP in packet:
            protocol = "ICMP"
            info = f"Type: {packet[ICMP].type} Code: {packet[ICMP].code}"

        output_line = (
            f"{Colors.CYAN}[{timestamp}]{Colors.ENDC} "
            f"{Colors.BOLD}{protocol:<5}{Colors.ENDC} | "
            f"{Colors.GREEN}{src_ip}:{src_port}{Colors.ENDC} -> "
            f"{Colors.BLUE}{dst_ip}:{dst_port}{Colors.ENDC} | {info}"
        )
        print(output_line)

        # Print payload snippet if available
        if show_payload and Raw in packet:
            payload_snippet = format_payload(packet[Raw].load)
            print(f"   {Colors.WARNING}└─ Payload Preview:{Colors.ENDC} {payload_snippet}")

        # Optional logging
        if log_file:
            clean_log = f"[{timestamp}] {protocol:<5} | {src_ip}:{src_port} -> {dst_ip}:{dst_port} | {info}\n"
            log_file.write(clean_log)

    # Handle ARP Packets
    elif ARP in packet:
        op_type = "Request" if packet[ARP].op == 1 else "Reply"
        arp_line = (
            f"{Colors.CYAN}[{timestamp}]{Colors.ENDC} "
            f"{Colors.BOLD}ARP  {Colors.ENDC} | "
            f"{op_type}: Who has {packet[ARP].pdst}? Tell {packet[ARP].psrc} ({packet[ARP].hwsrc})"
        )
        print(arp_line)
        if log_file:
            log_file.write(f"[{timestamp}] ARP | {op_type}: Who has {packet[ARP].pdst}? Tell {packet[ARP].psrc}\n")

def main():
    parser = argparse.ArgumentParser(
        description="CodeAlpha Basic Network Sniffer - Packet Analysis Tool",
        epilog="Note: Administrator / root privileges are required to capture raw network traffic."
    )
    parser.add_argument("-i", "--interface", help="Network interface to sniff on (default: default route)", default=None)
    parser.add_argument("-c", "--count", type=int, help="Number of packets to capture (default: 0 = infinite)", default=0)
    parser.add_argument("-f", "--filter", help="BPF filter expression (e.g. 'tcp', 'udp', 'port 80')", default=None)
    parser.add_argument("-o", "--output", help="Path to text log file to save captured summary", default=None)
    parser.add_argument("--no-payload", action="store_true", help="Hide payload snippet preview")

    args = parser.parse_args()

    print(f"{Colors.BOLD}{Colors.HEADER}===================================================={Colors.ENDC}")
    print(f"{Colors.BOLD}{Colors.HEADER}      CodeAlpha - Basic Network Packet Sniffer      {Colors.ENDC}")
    print(f"{Colors.BOLD}{Colors.HEADER}===================================================={Colors.ENDC}")
    print(f"Interface : {args.interface or 'Default'}")
    print(f"Filter    : {args.filter or 'None (All IP/ARP)'}")
    print(f"Count     : {'Infinite' if args.count == 0 else args.count}")
    print(f"Log File  : {args.output or 'Disabled'}")
    print(f"{Colors.BOLD}Press Ctrl+C at any time to stop capturing...{Colors.ENDC}\n")

    log_handle = None
    if args.output:
        try:
            log_handle = open(args.output, "a", encoding="utf-8")
        except Exception as e:
            print(f"{Colors.FAIL}Error opening log file: {e}{Colors.ENDC}")
            sys.exit(1)

    try:
        sniff(
            iface=args.interface,
            count=args.count,
            filter=args.filter,
            prn=lambda pkt: packet_callback(pkt, show_payload=(not args.no_payload), log_file=log_handle),
            store=False
        )
    except PermissionError:
        print(f"\n{Colors.FAIL}[!] Permission Denied:{Colors.ENDC} Capturing raw packets requires Administrator / root privileges.")
        print("Please run terminal / PowerShell as Administrator.")
    except Exception as e:
        print(f"\n{Colors.FAIL}[!] Error during packet capture:{Colors.ENDC} {e}")
        print("Hint: On Windows, make sure Npcap (or WinPcap) is installed with 'WinPcap API-compatible Mode' enabled.")
    finally:
        if log_handle:
            log_handle.close()
            print(f"\n[+] Log saved to {args.output}")
        print(f"{Colors.GREEN}[*] Sniffer session finished.{Colors.ENDC}")

if __name__ == "__main__":
    main()
