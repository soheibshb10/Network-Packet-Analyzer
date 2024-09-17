# Packet Sniffer Script
## Overview

This script is a simple packet sniffer that captures and analyzes network packets on a specified interface. It uses the scapy library to sniff packets and log details about various network protocols, including IP, TCP, UDP, ICMP, and ARP. The details are saved to a log file named sniffer_log.txt.
Features

    Captures and logs network packets.
    Analyzes and logs details for different network protocols:
        IP (includes TCP, UDP, and ICMP)
        ARP
    Logs packet details to sniffer_log.txt.
    Handles errors and provides usage instructions.

## Requirements

    Python 3.x
    scapy library

You can install the scapy library using:

bash

pip install scapy

How to Use

    Save the Script

    Save the provided script into a file, e.g., packet_sniffer.py.

    Run the Script

    Execute the script from a terminal or command prompt with the desired network interface as an argument:

    

python packet_sniffer.py <interface>

Replace <interface> with the name of the network interface you want to sniff on (e.g., eth0, wlan0).

Example:

    python packet_sniffer.py eth0

    Stop the Script

    To stop the packet sniffer, press Ctrl+C in the terminal or command prompt where the script is running.

    View the Log

    Packet details will be saved in sniffer_log.txt in the same directory as the script. The log file will contain information such as:
        Source and destination IP addresses.
        Source and destination ports (for TCP and UDP).
        Packet details for ICMP and ARP.
        Packet summaries for non-IP packets.

## Script Details

    Imports:
        import sys: For handling command-line arguments and system exit.
        from scapy.all import sniff, get_if_list, IP, TCP, UDP, ICMP, ARP: For packet sniffing and protocol analysis.

    Functions:
        analyze_protocol(packet): Analyzes packet layers (IP, TCP, UDP, ICMP, ARP) and returns a string with details.
        handle_packet(packet, log): Handles each packet, logs its details, and separates entries with a line.
        main(interface): Starts sniffing on the specified network interface and handles errors.

    Execution:
        The script checks if the specified interface exists.
        It starts packet sniffing and logs details to sniffer_log.txt.
        The script handles KeyboardInterrupt to allow graceful stopping and provides error messages for permission issues and other exceptions
