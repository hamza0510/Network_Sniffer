# Import Scapy packet sniffing tools
from scapy.all import sniff

# Import network protocol layers
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.dns import DNS
from scapy.layers.http import HTTPRequest

# For colored terminal output
from colorama import Fore, Style, init

# For Wireshark style table
from prettytable import PrettyTable

# Initialize colorama
init(autoreset=True)

# Create Wireshark-style packet table
packet_table = PrettyTable()

packet_table.field_names = [
    "No",
    "Source IP",
    "Destination IP",
    "Protocol",
    "Port",
    "Length",
    "Info"
]

packet_count = 0


def process_packet(packet):

    global packet_count
    packet_count += 1

    if packet.haslayer(IP):

        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        length = len(packet)

        protocol = "Other"
        port = "-"
        info = "-"

        # TCP Detection
        if packet.haslayer(TCP):
            protocol = Fore.GREEN + "TCP" + Style.RESET_ALL
            port = packet[TCP].dport

        # UDP Detection
        elif packet.haslayer(UDP):
            protocol = Fore.YELLOW + "UDP" + Style.RESET_ALL
            port = packet[UDP].dport

        # ICMP Detection
        elif packet.haslayer(ICMP):
            protocol = Fore.MAGENTA + "ICMP" + Style.RESET_ALL

        # DNS Detection
        if packet.haslayer(DNS):

            protocol = Fore.CYAN + "DNS" + Style.RESET_ALL

            try:
                query = packet[DNS].qd.qname.decode()
                info = f"Query: {query}"
            except:
                info = "DNS Query"

        # HTTP Detection
        if packet.haslayer(HTTPRequest):

            protocol = Fore.RED + "HTTP" + Style.RESET_ALL

            try:
                host = packet[HTTPRequest].Host.decode()
                path = packet[HTTPRequest].Path.decode()
                info = f"{host}{path}"

            except:
                info = "HTTP Request"

        # Add row to table
        packet_table.add_row([
            packet_count,
            src_ip,
            dst_ip,
            protocol,
            port,
            length,
            info
        ])

        print(packet_table)


print(Fore.GREEN + "Starting Network Sniffer...")
print("Press CTRL+C to stop\n")

# Start sniffing packets
sniff(
    prn=process_packet,
    store=False
)