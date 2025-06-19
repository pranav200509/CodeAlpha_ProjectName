from scapy.all import sniff, IP, TCP, UDP, ICMP # type: ignore
from datetime import datetime

def packet_callback(packet):
    print("\n--- Packet Captured ---")
    print(f"Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

    # Check for IP layer
    if IP in packet:
        ip_layer = packet[IP]
        print(f"Source IP: {ip_layer.src}")
        print(f"Destination IP: {ip_layer.dst}")
        
        # Identify protocol
        if TCP in packet:
            print("Protocol: TCP")
            print(f"Source Port: {packet[TCP].sport}")
            print(f"Destination Port: {packet[TCP].dport}")
            print(f"Flags: {packet[TCP].flags}")
            print(f"Sequence Number: {packet[TCP].seq}")
            print(f"Acknowledgment Number: {packet[TCP].ack}")
        elif UDP in packet:
            print("Protocol: UDP")
            print(f"Source Port: {packet[UDP].sport}")
            print(f"Destination Port: {packet[UDP].dport}")
        elif ICMP in packet:
            print("Protocol: ICMP")
            print(f"Type: {packet[ICMP].type}")
            print(f"Code: {packet[ICMP].code}")
        else:
            print(f"Protocol: {ip_layer.proto}")

        # Display payload
        payload = bytes(packet[IP].payload)
        print(f"Payload (first 50 bytes): {payload[:50]}")
    else:
        print("Non-IP packet detected")

# Start sniffing (you might need sudo/root privileges)
print("Starting packet capture... Press Ctrl+C to stop.\n")
sniff(prn=packet_callback, count=0)