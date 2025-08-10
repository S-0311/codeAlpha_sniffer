from scapy.all import sniff, IP

def process_packet(packet):
    if packet.haslayer(IP):
        source_ip = packet[IP].src
        destination_ip = packet[IP].dst
        protocol = packet[IP].proto

        print(" New Packet Captured:")
        print(f" From: {source_ip}")
        print(f" To:   {destination_ip}")
        print(f" Protocol Number: {protocol}")
        print("---------------------------------------------")

print(" Starting packet capture... (waiting for 10 packets)\n")

sniff(
    prn=process_packet,
    count=10,
    iface="Wi-Fi",
    store=False
)
