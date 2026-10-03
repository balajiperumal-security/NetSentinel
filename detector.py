from scapy.all import sniff, IP, TCP, UDP, ICMP
from collections import Counter
from datetime import datetime

packet_count = 0
protocol_count = Counter()
source_count = Counter()
port_count = Counter()

def analyze_packet(packet):
    global packet_count

    if IP not in packet:
        return

    packet_count += 1

    src = packet[IP].src
    dst = packet[IP].dst

    if TCP in packet:
        protocol = "TCP"
        dport = packet[TCP].dport
        port_count[dport] += 1

    elif UDP in packet:
        protocol = "UDP"
        dport = packet[UDP].dport
        port_count[dport] += 1

    elif ICMP in packet:
        protocol = "ICMP"
        dport = "-"
        
    else:
        protocol = "OTHER"
        dport = "-"

    protocol_count[protocol] += 1
    source_count[src] += 1

    print(
        f"[{datetime.now().strftime('%H:%M:%S')}] "
        f"{src} -> {dst} | {protocol} | Port: {dport}"
    )

    # Simple defensive detection
    if source_count[src] == 20:
        print(f"\n[ALERT] High packet activity from {src}\n")

    if len(port_count) == 10:
        print(
            f"\n[ALERT] Multiple destination ports observed "
            f"from monitored traffic\n"
        )

print("=" * 60)
print("              NETSENTINEL DETECTOR")
print("=" * 60)
print("Monitoring authorized/local network traffic...")
print("Press CTRL+C to stop.\n")

sniff(prn=analyze_packet, store=False)
