# Zainab Batool, student of Business Data Analytics at COMSATS University Islamabad
# CodeAlpha Cyber Security Internship - Task 1: Basic Network Sniffer
#
# Is program ko sirf apne network / apni machine par chalayen (educational use).
# Run (admin/root zaroori hai):
#   Linux/Mac : sudo python3 sniffer.py
#   Windows   : Command Prompt "Run as administrator" -> python sniffer.py
#   (Windows par Npcap install hona chahiye: https://npcap.com)

from scapy.all import sniff, IP, TCP, UDP, ICMP, Raw
from datetime import datetime

packet_count = 0


def get_protocol_name(packet):
    """Packet ka protocol name wapas karta hai."""
    if packet.haslayer(TCP):
        return "TCP"
    elif packet.haslayer(UDP):
        return "UDP"
    elif packet.haslayer(ICMP):
        return "ICMP"
    else:
        return "Other"


def process_packet(packet):
    """Har captured packet par ye function chalta hai."""
    global packet_count

    # Sirf IP packets analyze karenge
    if not packet.haslayer(IP):
        return

    packet_count += 1
    ip_layer = packet[IP]
    protocol = get_protocol_name(packet)
    time_now = datetime.now().strftime("%H:%M:%S")

    print("=" * 60)
    print(f"Packet #{packet_count}   Time: {time_now}")
    print(f"Source IP      : {ip_layer.src}")
    print(f"Destination IP : {ip_layer.dst}")
    print(f"Protocol       : {protocol}")
    print(f"Packet Length  : {len(packet)} bytes")
    print(f"TTL            : {ip_layer.ttl}")

    # TCP / UDP ke ports
    if packet.haslayer(TCP):
        print(f"Source Port    : {packet[TCP].sport}")
        print(f"Dest Port      : {packet[TCP].dport}")
        print(f"TCP Flags      : {packet[TCP].flags}")
    elif packet.haslayer(UDP):
        print(f"Source Port    : {packet[UDP].sport}")
        print(f"Dest Port      : {packet[UDP].dport}")

    # Payload (data) - sirf pehle 50 bytes dikhayenge
    if packet.haslayer(Raw):
        payload = bytes(packet[Raw].load)[:50]
        print(f"Payload (50 B) : {payload}")
    else:
        print("Payload        : (koi data nahi)")


def main():
    print("Network Sniffer start ho gaya... Rukne ke liye Ctrl+C dabayen.\n")
    # count=20 ka matlab 20 packets capture karke ruk jayega.
    # store=False se memory bachti hai.
    sniff(prn=process_packet, count=20, store=False)
    print(f"\nTotal {packet_count} IP packets analyze hue.")


if __name__ == "__main__":
    main()
