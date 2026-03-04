from scapy.all import sniff
from scapy.layers.inet import IP, TCP, UDP, ICMP
import datetime


def packet_callback(packet):

    if packet.haslayer(IP):

        timestamp = datetime.datetime.now()

        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        length = len(packet)

        protocol = "Other"

        if packet.haslayer(TCP):
            protocol = "TCP"

        elif packet.haslayer(UDP):
            protocol = "UDP"

        elif packet.haslayer(ICMP):
            protocol = "ICMP"

        print("="*50)
        print(f"Time        : {timestamp}")
        print(f"Source IP   : {src_ip}")
        print(f"Destination : {dst_ip}")
        print(f"Protocol    : {protocol}")
        print(f"Packet Size : {length} bytes")
        print("="*50)


print("Network Sniffer Started... Press CTRL+C to stop")

sniff(prn=packet_callback, store=False)