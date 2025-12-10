from scapy.all import IP, TCP, Ether, Padding, wrpcap, Raw
from scapy.contrib.bgp import *
import time
import random
import os

def gauss_delay(mu_ms, sigma_ms):
    d = max(0, random.gauss(mu_ms, sigma_ms) / 1000.0)
    time.sleep(d)

# Parameters (toy lab values, safe)
src_ip = "10.0.0.1"
dst_ip = "10.0.0.2"
src_mac = "00:11:22:33:44:55"
dst_mac = "00:55:44:33:22:11"
src_as = 65010
dst_as = 65020
nlri = ["203.0.113.0/24"]
as_path = [src_as]
next_hop = "10.0.0.1"
sport = 43001
dport = 179
mu = 10
sigma = 2

pkts = []

# TCP options
tcp_options = [('MSS', 1460)]

# Generate realistic IP ID values (high random values)
src_ip_id = random.randint(20000, 65000)
dst_ip_id = random.randint(20000, 65000)

# TCP 3-way handshake
seq_a = 1000
seq_b = 5000

# SYN packet - Src to Dst (Client to BGP Server)
syn_pkt = Ether(src=src_mac, dst=dst_mac)/IP(src=src_ip, dst=dst_ip, ttl=1, flags="DF", tos=0xC0, id=src_ip_id)/TCP(sport=sport, dport=dport, flags="S", seq=seq_a, window=16384, options=tcp_options)
if len(syn_pkt) < 60:
    pad_len = 60 - len(syn_pkt)
    syn_pkt = syn_pkt/Padding(load=b'\x00' * pad_len)
pkts.append(syn_pkt)

# SYN-ACK packet - Dst to Src (BGP Server to Client)
synack_pkt = Ether(src=dst_mac, dst=src_mac)/IP(src=dst_ip, dst=src_ip, ttl=1, flags=0, tos=0xC0, id=dst_ip_id)/TCP(sport=dport, dport=sport, flags="SA", seq=seq_b, ack=seq_a+1, window=16384, options=tcp_options)
if len(synack_pkt) < 60:
    pad_len = 60 - len(synack_pkt)
    synack_pkt = synack_pkt/Padding(load=b'\x00' * pad_len)
pkts.append(synack_pkt)

# ACK packet - Src to Dst
ack_pkt = Ether(src=src_mac, dst=dst_mac)/IP(src=src_ip, dst=dst_ip, ttl=1, flags="DF", tos=0xC0, id=src_ip_id+1)/TCP(sport=sport, dport=dport, flags="A", seq=seq_a+1, ack=seq_b+1, window=16384)
if len(ack_pkt) < 60:
    pad_len = 60 - len(ack_pkt)
    ack_pkt = ack_pkt/Padding(load=b'\x00' * pad_len)
pkts.append(ack_pkt)

# Create BGP capabilities for OPEN message
# 1. Multiprotocol IPv4 Unicast capability
mp_cap = BGPCapMultiprotocol(code=1, length=4, afi=1, safi=1)

# 2. Route Refresh Capability (Cisco)
rr_cisco = BGPCapGeneric(code=128, length=0)

# 3. Route Refresh standard capability
rr_std = BGPCapGeneric(code=2, length=0)

# 4. Enhanced route refresh capability
err_cap = BGPCapGeneric(code=70, length=0)

# 5. Support for 4-octet AS capability for source
as4_cap_src = BGPCapFourBytesASN(code=65, length=4, asn=src_as)

# 5. Support for 4-octet AS capability for destination
as4_cap_dst = BGPCapFourBytesASN(code=65, length=4, asn=dst_as)

# Create BGP Optional Parameters with correct field names
opt_params_src = [
    BGPOptParam(param_type=2, param_length=len(mp_cap), param_value=mp_cap),
    BGPOptParam(param_type=2, param_length=len(rr_cisco), param_value=rr_cisco),
    BGPOptParam(param_type=2, param_length=len(rr_std), param_value=rr_std),
    BGPOptParam(param_type=2, param_length=len(err_cap), param_value=err_cap),
    BGPOptParam(param_type=2, param_length=len(as4_cap_src), param_value=as4_cap_src)
]

# Create separate set for destination with its own AS number
opt_params_dst = opt_params_src.copy()
# Replace the last parameter (AS4) with destination AS
opt_params_dst[-1] = BGPOptParam(
    param_type=2, 
    param_length=len(as4_cap_dst),
    param_value=as4_cap_dst
)

# Create BGP OPEN message with capabilities
open_a = BGPHeader(type=1)/BGPOpen(
    version=4, 
    my_as=src_as, 
    hold_time=180,
    bgp_id="1.1.1.1",
    opt_param_len=None,  #  Scapy calculate
    opt_params=opt_params_src
)

# Now create the packet and add to list(takes the BGP OPEN message (open_a) and actually puts it inside a TCP segment and then wraps it with IP + Ethernet)
open_a_pkt = Ether(src=src_mac, dst=dst_mac)/IP(src=src_ip, dst=dst_ip, ttl=1, flags="DF", tos=0xC0, id=src_ip_id+2)/TCP(sport=sport, dport=dport, flags="PA", seq=ack_pkt[TCP].seq, ack=ack_pkt[TCP].ack, window=16384)/open_a
if len(open_a_pkt) < 60:
    pad_len = 60 - len(open_a_pkt)
    open_a_pkt = open_a_pkt/Padding(load=b'\x00' * pad_len)
pkts.append(open_a_pkt)
seq_a += len(open_a)

# BGP OPEN from dst
open_b = BGPHeader(type=1)/BGPOpen(
    version=4, 
    my_as=dst_as, 
    hold_time=180,
    bgp_id="2.2.2.2",
    opt_param_len=None,
    opt_params=opt_params_dst
)

open_b_pkt = Ether(src=dst_mac, dst=src_mac)/IP(src=dst_ip, dst=src_ip, ttl=1, flags=0, tos=0xC0, id=dst_ip_id+1)/TCP(sport=dport, dport=sport, flags="PA", seq=synack_pkt[TCP].seq+1, ack=seq_a, window=16384)/open_b
if len(open_b_pkt) < 60:
    pad_len = 60 - len(open_b_pkt)
    open_b_pkt = open_b_pkt/Padding(load=b'\x00' * pad_len)
pkts.append(open_b_pkt)
seq_b += len(open_b)

# KEEPALIVE from src
keep_a = BGPKeepAlive()
keep_a_pkt = Ether(src=src_mac, dst=dst_mac)/IP(src=src_ip, dst=dst_ip, ttl=1, flags="DF", tos=0xC0, id=src_ip_id+3)/TCP(sport=sport, dport=dport, flags="PA", seq=seq_a, ack=seq_b, window=16384)/keep_a
if len(keep_a_pkt) < 60:
    pad_len = 60 - len(keep_a_pkt)
    keep_a_pkt = keep_a_pkt/Padding(load=b'\x00' * pad_len)
pkts.append(keep_a_pkt)
seq_a += len(keep_a)  

# KEEPALIVE from dst
keep_b = BGPKeepAlive()
keep_b_pkt = Ether(src=dst_mac, dst=src_mac)/IP(src=dst_ip, dst=src_ip, ttl=1, flags=0, tos=0xC0, id=dst_ip_id+2)/TCP(sport=dport, dport=sport, flags="PA", seq=seq_b, ack=seq_a, window=16384)/keep_b
if len(keep_b_pkt) < 60:
    pad_len = 60 - len(keep_b_pkt)
    keep_b_pkt = keep_b_pkt/Padding(load=b'\x00' * pad_len)
pkts.append(keep_b_pkt)
seq_b += len(keep_b)  

# BGP UPDATE with correctly formatted path attributes
update = BGPHeader(type=2)/BGPUpdate()

# 1. ORIGIN attribute
origin = BGPPathAttr(type_flags=0x40, type_code=1)
origin.attribute = BGPPAOrigin(origin=0)  # IGP = 0

# 2. AS_PATH attribute with proper AS_SEQUENCE
as_path_attr = BGPPathAttr(type_flags=0x40, type_code=2)

# Create an AS_PATH segment according to the structure in the Scapy code
from scapy.contrib.bgp import BGPPAASPath

# Create a proper AS_PATH segment
as_path_segment = BGPPAASPath()
# Create a segment with an AS_SEQUENCE containing src_as
segment = BGPPAASPath.ASPathSegment(
    segment_type=2,  # AS_SEQUENCE
    segment_length=1,
    segment_value=[src_as]
)
# Add the segment to the AS_PATH
as_path_segment.segments = [segment]
as_path_attr.attribute = as_path_segment


# 3. NEXT_HOP attribute
next_hop_attr = BGPPathAttr(type_flags=0x40, type_code=3)
next_hop_attr.attribute = BGPPANextHop(next_hop=next_hop)

# 4. MULTI_EXIT_DISC attribute (MED)
med_attr = BGPPathAttr(type_flags=0x80, type_code=4)
med_attr.attribute = BGPPAMultiExitDisc(med=0)

# Combine path attributes
update.path_attr = [origin, as_path_attr, next_hop_attr, med_attr]

# Add NLRI
for prefix in nlri:
    update.nlri.append(BGPNLRI_IPv4(prefix=prefix))

# Send UPDATE
update_pkt = Ether(src=src_mac, dst=dst_mac)/IP(src=src_ip, dst=dst_ip, ttl=1, flags="DF", tos=0xC0, id=src_ip_id+4)/TCP(sport=sport, dport=dport, flags="PA", seq=seq_a, ack=seq_b, window=16384)/update
if len(update_pkt) < 60:
    pad_len = 60 - len(update_pkt)
    update_pkt = update_pkt/Padding(load=b'\x00' * pad_len)
pkts.append(update_pkt)
seq_a += len(update)

# Create pcaps directory if it doesn't exist
os.makedirs("pcaps", exist_ok=True)

# Write to pcap
wrpcap("pcaps/normal_ebgp.pcap", pkts)
print("✅ Wrote pcaps/normal_ebgp.pcap")
