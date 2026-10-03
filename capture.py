from scapy.all import sniff, IP, TCP, UDP, ICMP
from datetime import datetime

def process_packet(packet):

    if IP not in packet:
        return

    src_ip = packet[IP].src
    dst_ip = packet[IP].dst
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    print("\n" + "=" * 60)
    print(f"Time       : {timestamp}")
    print(f"Source IP  : {src_ip}")
    print(f"Destination: {dst_ip}")

    if TCP in packet:
        print("Protocol   : TCP")
        print(f"Src Port   : {packet[TCP].sport}")
        print(f"Dst Port   : {packet[TCP].dport}")
        print(f"Flags      : {packet[TCP].flags}")

    elif UDP in packet:
        print("Protocol   : UDP")
        print(f"Src Port   : {packet[UDP].sport}")
        print(f"Dst Port   : {packet[UDP].dport}")

    elif ICMP in packet:
        print("Protocol   : ICMP")
        print(f"Type       : {packet[ICMP].type}")
        print(f"Code       : {packet[ICMP].code}")

    else:
        print("Protocol   : Other")

    print("=" * 60)


print("[*] NetSentinel Packet Capture")
print("[*] Starting packet sniffing...")
print("[*] Press Ctrl+C to stop.")

sniff(
    prn=process_packet,
    store=False
)
