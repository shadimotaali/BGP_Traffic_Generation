from scapy.all import IP, TCP, wrpcap
pkt = IP(dst="10.0.0.1")/TCP(dport=179)
wrpcap("pcaps/_sanity.pcap", [pkt])
print("Wrote pcaps/_sanity.pcap")
