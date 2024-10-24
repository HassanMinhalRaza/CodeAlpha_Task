from scapy.all import sniff, IP

def packet_callback(packet):
    # Filter for IP packets
    if IP in packet:
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        print(f"Source: {ip_src} -> Destination: {ip_dst}")

# Start sniffing on the default interface
print("Starting to sniff...")
sniff(prn=packet_callback, filter="ip")  # Removed store=0

from scapy.all import get_if_list

print(get_if_list())