import sys
from scapy.all import sniff, get_if_list, IP, TCP, UDP, ICMP, ARP

def analyze_protocol(packet):
    """Analyze and log details of different protocols in the packet."""
    details = ""

    if packet.haslayer(IP):
        ip_layer = packet[IP]
        details += f"IP Layer:\n"
        details += f"  Source IP: {ip_layer.src}\n"
        details += f"  Destination IP: {ip_layer.dst}\n"
        details += f"  Protocol: {ip_layer.proto}\n"
        
        if packet.haslayer(TCP):
            tcp_layer = packet[TCP]
            details += f"TCP Layer:\n"
            details += f"  Source Port: {tcp_layer.sport}\n"
            details += f"  Destination Port: {tcp_layer.dport}\n"
            details += f"  Sequence Number: {tcp_layer.seq}\n"
            details += f"  Acknowledgment Number: {tcp_layer.ack}\n"
        
        elif packet.haslayer(UDP):
            udp_layer = packet[UDP]
            details += f"UDP Layer:\n"
            details += f"  Source Port: {udp_layer.sport}\n"
            details += f"  Destination Port: {udp_layer.dport}\n"
        
        elif packet.haslayer(ICMP):
            icmp_layer = packet[ICMP]
            details += f"ICMP Layer:\n"
            details += f"  Type: {icmp_layer.type}\n"
            details += f"  Code: {icmp_layer.code}\n"
            details += f"  Identifier: {icmp_layer.id}\n"
            details += f"  Sequence Number: {icmp_layer.seq}\n"
        
        else:
            details += f"Other IP Protocol: {ip_layer.proto}\n"

    elif packet.haslayer(ARP):
        arp_layer = packet[ARP]
        details += f"ARP Layer:\n"
        details += f"  Operation: {arp_layer.op}\n"
        details += f"  Source MAC: {arp_layer.hwsrc}\n"
        details += f"  Source IP: {arp_layer.psrc}\n"
        details += f"  Destination MAC: {arp_layer.hwdst}\n"
        details += f"  Destination IP: {arp_layer.pdst}\n"

    else:
        details += f"Non-IP Packet:\n"
        details += f"  Summary: {packet.summary()}\n"

    return details

def handle_packet(packet, log):
    """Handle and log packet details."""
    details = analyze_protocol(packet)
    log.write(details + "\n")
    log.write("-" * 40 + "\n")

def main(interface):
    """Main function to start sniffing on the specified interface."""
    # Check if the interface exists
    interfaces = get_if_list()
    if interface not in interfaces:
        print(f"Error: The interface '{interface}' is not available.")
        print("Available interfaces:")
        for iface in interfaces:
            print(f" - {iface}")
        sys.exit(1)

    # Create log file name based on interface
    logfile_name = f"sniffer_log.txt"
    # Open log file for writing
    with open(logfile_name, 'w') as logfile:
        try:
            # Start packet sniffing on specified interface
            print(f"Sniffing on interface {interface}. Press Ctrl+C to stop.")
            sniff(iface=interface, prn=lambda pkt: handle_packet(pkt, logfile), store=0)
        except KeyboardInterrupt:
            print("\nSniffer stopped.")
            sys.exit(0)
        except PermissionError as e:
            print(f"Permission error: {e}. You may need to run this script as root.")
            sys.exit(1)
        except Exception as e:
            print(f"An error occurred: {e}")
            sys.exit(1)

# Check if the script is being run directly
if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python packet_sniffer.py <interface>")
        sys.exit(1)

    # Call the main function with the specified interface
    main(sys.argv[1])
