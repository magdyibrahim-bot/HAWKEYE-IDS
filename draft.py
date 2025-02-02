from scapy.all import rdpcap, wrpcap

# List of input PCAP files
pcap_files = ["PCAP/arpspoof.pcap", "PCAP/http_slowloris.pcap"]

# Read packets from all PCAP files and merge
all_packets = []
for file in pcap_files:
    packets = rdpcap(file)
    all_packets.extend(packets)

# Write the merged packets to a new PCAP file
wrpcap("merged_output.pcap", all_packets)

print("PCAP files merged successfully!")
