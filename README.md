# packet-snifferPacket Sniffer

A simple, yet powerful, packet sniffer tool developed to capture, analyze, and inspect network traffic in real-time. This tool can capture packets over various network interfaces and decode them to provide valuable insights into the data being transmitted.
Features:

    Real-Time Packet Capture: Intercepts and logs network traffic on selected network interfaces.
    Protocol Decoding: Decodes and displays information for common network protocols such as TCP, UDP, HTTP, and DNS.
    Customizable Filters: Allows users to apply filters to capture only the traffic of interest (e.g., by IP address, protocol, or port).
    Detailed Data Inspection: Provides detailed packet information including headers, payloads, and flags.
    Cross-Platform Compatibility: Built to work on multiple operating systems such as Linux, macOS, and Windows.

Use Cases:

    Network monitoring and troubleshooting.
    Security assessments and vulnerability scanning.
    Analyzing network performance and traffic patterns.
    Educational purposes for learning about network protocols.

Requirements:

    Python 3.x+
    Scapy library (for packet crafting and analysis)
    Admin privileges for capturing packets on network interfaces

Installation:

git clone https://github.com/gangadharrelangi/packet-sniffer.git
cd packet-sniffer

Usage:

To start capturing packets, run the following command:

python sniffer.py (for gui)
python sniffer.py --cli (for cli)
