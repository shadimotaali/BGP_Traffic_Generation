from scapy.all import IP, IPv6, TCP, Ether, Padding, wrpcap, Raw
from scapy.contrib.bgp import *
import time
import random
import os

def gauss_delay(mu_ms, sigma_ms):
    d = max(0, random.gauss(mu_ms, sigma_ms) / 1000.0)
    time.sleep(d)

# Parameters (toy lab values, safe)
# IPv4 parameters
src_ipv4 = "10.0.0.1"
dst_ipv4 = "10.0.0.2"
src_mac = "00:11:22:33:44:55"
dst_mac = "00:55:44:33:22:11"
src_as = 65010
dst_as = 65020
ipv4_nlri = ["203.0.113.0/24", "198.51.100.0/24"]
ipv4_next_hop = src_ipv4

# IPv6 parameters
src_ipv6 = "2001:db8:1::1"
dst_ipv6 = "2001:db8:1::2"
ipv6_nlri = ["2001:db8:2::/48", "2001:db8:3::/48"]
ipv6_next_hop = src_ipv6


# Aggregator parameters - for AGGREGATOR attribute
aggregator_as = src_as    # AS that performed the aggregation
aggregator_ip = "192.0.2.10"  # IP of the router that performed aggregation

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

# ======================================
# PART 1: BGP Session over IPv4 transport
# ======================================
print("[+] Generating BGP session over IPv4 transport...")

# TCP 3-way handshake for IPv4 session
seq_a_v4 = 1000
seq_b_v4 = 5000

# SYN packet - Src to Dst (Client to BGP Server)
syn_pkt = Ether(src=src_mac, dst=dst_mac)/IP(src=src_ipv4, dst=dst_ipv4, ttl=1, flags="DF", tos=0xC0, id=src_ip_id)/TCP(sport=sport, dport=dport, flags="S", seq=seq_a_v4, window=16384, options=tcp_options)
if len(syn_pkt) < 60:
    pad_len = 60 - len(syn_pkt)
    syn_pkt = syn_pkt/Padding(load=b'\x00' * pad_len)
pkts.append(syn_pkt)

# SYN-ACK packet - Dst to Src (BGP Server to Client)
synack_pkt = Ether(src=dst_mac, dst=src_mac)/IP(src=dst_ipv4, dst=src_ipv4, ttl=1, flags=0, tos=0xC0, id=dst_ip_id)/TCP(sport=dport, dport=sport, flags="SA", seq=seq_b_v4, ack=seq_a_v4+1, window=16384, options=tcp_options)
if len(synack_pkt) < 60:
    pad_len = 60 - len(synack_pkt)
    synack_pkt = synack_pkt/Padding(load=b'\x00' * pad_len)
pkts.append(synack_pkt)

# ACK packet - Src to Dst
ack_pkt = Ether(src=src_mac, dst=dst_mac)/IP(src=src_ipv4, dst=dst_ipv4, ttl=1, flags="DF", tos=0xC0, id=src_ip_id+1)/TCP(sport=sport, dport=dport, flags="A", seq=seq_a_v4+1, ack=seq_b_v4+1, window=16384)
if len(ack_pkt) < 60:
    pad_len = 60 - len(ack_pkt)
    ack_pkt = ack_pkt/Padding(load=b'\x00' * pad_len)
pkts.append(ack_pkt)

# Create BGP capabilities for OPEN message (for both IPv4 and IPv6 sessions)
# 1. Multiprotocol IPv4 Unicast capability
mp_ipv4_cap = BGPCapMultiprotocol(code=1, length=4, afi=1, safi=1)

# 2. Multiprotocol IPv6 Unicast capability
mp_ipv6_cap = BGPCapMultiprotocol(code=1, length=4, afi=2, safi=1)

# 3. Route Refresh Capability (Cisco)
rr_cisco = BGPCapGeneric(code=128, length=0)

# 4. Route Refresh standard capability
rr_std = BGPCapGeneric(code=2, length=0)

# 5. Enhanced route refresh capability
err_cap = BGPCapGeneric(code=70, length=0)

# 6. Support for 4-octet AS capability for source
as4_cap_src = BGPCapFourBytesASN(code=65, length=4, asn=src_as)

# 7. Support for 4-octet AS capability for destination
as4_cap_dst = BGPCapFourBytesASN(code=65, length=4, asn=dst_as)

# Create BGP Optional Parameters with correct field names (both IPv4 & IPv6 capabilities)
opt_params_src = [
    BGPOptParam(param_type=2, param_length=len(mp_ipv4_cap), param_value=mp_ipv4_cap),
    BGPOptParam(param_type=2, param_length=len(mp_ipv6_cap), param_value=mp_ipv6_cap),
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

# Create BGP OPEN message with capabilities for IPv4 session
open_a_v4 = BGPHeader(type=1)/BGPOpen(
    version=4, 
    my_as=src_as, 
    hold_time=180,
    bgp_id="1.1.1.1",
    opt_param_len=None,  #  Scapy calculate
    opt_params=opt_params_src
)

# Send OPEN over IPv4
open_a_pkt_v4 = Ether(src=src_mac, dst=dst_mac)/IP(src=src_ipv4, dst=dst_ipv4, ttl=1, flags="DF", tos=0xC0, id=src_ip_id+2)/TCP(sport=sport, dport=dport, flags="PA", seq=ack_pkt[TCP].seq, ack=ack_pkt[TCP].ack, window=16384)/open_a_v4
if len(open_a_pkt_v4) < 60:
    pad_len = 60 - len(open_a_pkt_v4)
    open_a_pkt_v4 = open_a_pkt_v4/Padding(load=b'\x00' * pad_len)
pkts.append(open_a_pkt_v4)
seq_a_v4 += len(open_a_v4)

# BGP OPEN from dst over IPv4
open_b_v4 = BGPHeader(type=1)/BGPOpen(
    version=4, 
    my_as=dst_as, 
    hold_time=180,
    bgp_id="2.2.2.2",
    opt_param_len=None,
    opt_params=opt_params_dst
)

open_b_pkt_v4 = Ether(src=dst_mac, dst=src_mac)/IP(src=dst_ipv4, dst=src_ipv4, ttl=1, flags=0, tos=0xC0, id=dst_ip_id+1)/TCP(sport=dport, dport=sport, flags="PA", seq=synack_pkt[TCP].seq+1, ack=seq_a_v4, window=16384)/open_b_v4
if len(open_b_pkt_v4) < 60:
    pad_len = 60 - len(open_b_pkt_v4)
    open_b_pkt_v4 = open_b_pkt_v4/Padding(load=b'\x00' * pad_len)
pkts.append(open_b_pkt_v4)
seq_b_v4 += len(open_b_v4)

# KEEPALIVE from src over IPv4
keep_a_v4 = BGPKeepAlive()
keep_a_pkt_v4 = Ether(src=src_mac, dst=dst_mac)/IP(src=src_ipv4, dst=dst_ipv4, ttl=1, flags="DF", tos=0xC0, id=src_ip_id+3)/TCP(sport=sport, dport=dport, flags="PA", seq=seq_a_v4, ack=seq_b_v4, window=16384)/keep_a_v4
if len(keep_a_pkt_v4) < 60:
    pad_len = 60 - len(keep_a_pkt_v4)
    keep_a_pkt_v4 = keep_a_pkt_v4/Padding(load=b'\x00' * pad_len)
pkts.append(keep_a_pkt_v4)
seq_a_v4 += len(keep_a_v4)  

# KEEPALIVE from dst over IPv4
keep_b_v4 = BGPKeepAlive()
keep_b_pkt_v4 = Ether(src=dst_mac, dst=src_mac)/IP(src=dst_ipv4, dst=src_ipv4, ttl=1, flags=0, tos=0xC0, id=dst_ip_id+2)/TCP(sport=dport, dport=sport, flags="PA", seq=seq_b_v4, ack=seq_a_v4, window=16384)/keep_b_v4
if len(keep_b_pkt_v4) < 60:
    pad_len = 60 - len(keep_b_pkt_v4)
    keep_b_pkt_v4 = keep_b_pkt_v4/Padding(load=b'\x00' * pad_len)
pkts.append(keep_b_pkt_v4)
seq_b_v4 += len(keep_b_v4)  

# Prepare common path attributes for both IPv4 and IPv6 advertisements
# 1. ORIGIN attribute (mandatory)
origin = BGPPathAttr(type_flags=0x40, type_code=1)
origin.attribute = BGPPAOrigin(origin=0)  # IGP = 0

# 2. AS_PATH attribute (mandatory)
as_path_attr = BGPPathAttr(type_flags=0x40, type_code=2)

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

# 3. MULTI_EXIT_DISC attribute (MED)
med_attr = BGPPathAttr(type_flags=0x80, type_code=4)
med_attr.attribute = BGPPAMultiExitDisc(med=100)  # A typical MED value

# 4. LOCAL_PREF attribute (widely used in real world)
local_pref_attr = BGPPathAttr(type_flags=0x40, type_code=5)
local_pref_attr.attribute = BGPPALocalPref(local_pref=200)  # Higher LOCAL_PREF = preferred path

# 5. ATOMIC_AGGREGATE attribute (common for aggregated routes)
atomic_aggr_attr = BGPPathAttr(type_flags=0x40, type_code=6)
atomic_aggr_attr.attribute = BGPPAAtomicAggregate()  # No value, just a flag

# 6. AGGREGATOR attribute (provides info about the aggregating router)
aggregator_attr = BGPPathAttr(type_flags=0x40|0x80, type_code=7)  # Optional + Transitive
aggregator_attr.attribute = BGPPAAggregator(aggregator_asn=aggregator_as, 
                                          speaker_address=aggregator_ip)

# 7. COMMUNITIES attribute (widely used for route tagging and filtering)
# Based on Scapy's implementation, we need to create a list of individual communities
communities_list = []
# No-export community
communities_list.append(BGPPACommunity(community=0xFFFFFF01))  # NO_EXPORT
# Custom community
communities_list.append(BGPPACommunity(community=src_as<<16|200))  # src_as:200

# Create the communities path attribute with the list of communities
communities_attr = BGPPathAttr(type_flags=0x40|0x80, type_code=8)  # Optional + Transitive
communities_attr.attribute = communities_list


# 10. EXTENDED COMMUNITIES attribute (used for RT, SOO, etc.)
ext_communities_attr = BGPPathAttr(type_flags=0x80|0x40, type_code=16)  # Optional + Transitive

# Create two extended communities
ext_comm_list = []

# Create a route target extended community (type 0x01, subtype 0x02)
# IPv4-Address-Specific with Route Target subtype
route_target = BGPPAExtCommunity(type_high=0x01, type_low=0x02)
# The value is an IPv4AddressSpecific structure
route_target.value = BGPPAExtCommIPv4AddressSpecific(
    global_administrator=0xC0A80001,  # 192.168.0.1 as an integer
    local_administrator=1             # Local admin value
)
ext_comm_list.append(route_target)

# Create a site of origin extended community (type 0x01, subtype 0x03)
# IPv4-Address-Specific with Route Origin subtype
site_of_origin = BGPPAExtCommunity(type_high=0x01, type_low=0x03)
# The value is an IPv4AddressSpecific structure
site_of_origin.value = BGPPAExtCommIPv4AddressSpecific(
    global_administrator=0xC0A80002,  # 192.168.0.2 as an integer
    local_administrator=2             # Local admin value
)
ext_comm_list.append(site_of_origin)

# Assign the list to the attribute
ext_communities_attr.attribute = ext_comm_list

# IPv4 advertisement directly in NLRI over IPv4 transport
ipv4_update_v4 = BGPHeader(type=2)/BGPUpdate()

# NEXT_HOP attribute for direct IPv4 advertisement (mandatory)
next_hop_attr_v4 = BGPPathAttr(type_flags=0x40, type_code=3)
next_hop_attr_v4.attribute = BGPPANextHop(next_hop=ipv4_next_hop)

# Combine path attributes for direct IPv4 advertisement (following typical order)
ipv4_update_v4.path_attr = [
    origin,               # 1. ORIGIN (mandatory)
    as_path_attr,         # 2. AS_PATH (mandatory) 
    next_hop_attr_v4,     # 3. NEXT_HOP (mandatory)
    med_attr,             # 4. MED (optional)
    local_pref_attr,      # 5. LOCAL_PREF (optional)
    atomic_aggr_attr,     # 6. ATOMIC_AGGREGATE (if present)
    aggregator_attr,      # 7. AGGREGATOR (if present)
    communities_attr,     # 10. COMMUNITIES (if present)
    ext_communities_attr  # 11. EXTENDED COMMUNITIES (if present)
]

# Add IPv4 NLRI directly in the UPDATE
for prefix in ipv4_nlri:
    ipv4_update_v4.nlri.append(BGPNLRI_IPv4(prefix=prefix))

# Send IPv4 UPDATE over IPv4 session
ipv4_update_pkt_v4 = Ether(src=src_mac, dst=dst_mac)/IP(src=src_ipv4, dst=dst_ipv4, ttl=1, flags="DF", tos=0xC0, id=src_ip_id+4)/TCP(sport=sport, dport=dport, flags="PA", seq=seq_a_v4, ack=seq_b_v4, window=16384)/ipv4_update_v4
if len(ipv4_update_pkt_v4) < 60:
    pad_len = 60 - len(ipv4_update_pkt_v4)
    ipv4_update_pkt_v4 = ipv4_update_pkt_v4/Padding(load=b'\x00' * pad_len)
pkts.append(ipv4_update_pkt_v4)
seq_a_v4 += len(ipv4_update_v4)

# IPv6 advertisement via MP_REACH_NLRI over IPv4 transport
ipv6_update_v4 = BGPHeader(type=2)/BGPUpdate()

# MP_REACH_NLRI attribute for IPv6 (last in order)
mp_reach_attr_v4 = BGPPathAttr(type_flags=0x80, type_code=14)  # MP_REACH_NLRI type code is 14

# Prepare IPv6 prefixes for MP_REACH_NLRI
ipv6_nlri_objs = []
for prefix in ipv6_nlri:
    ipv6_nlri_objs.append(BGPNLRI_IPv6(prefix=prefix))

# Create the MP_REACH_NLRI attribute
mp_reach_v4 = BGPPAMPReachNLRI(
    afi=2,                # IPv6 = 2
    safi=1,               # Unicast = 1
    nh_addr_len=16,       # IPv6 address length
    nh_v6_addr=ipv6_next_hop,
    reserved=0,
    nlri=ipv6_nlri_objs
)

mp_reach_attr_v4.attribute = mp_reach_v4

# Combine path attributes for IPv6 over IPv4 update (following typical order)
# Note: NO next_hop_attr here since it's in the MP_REACH_NLRI for IPv6 prefixes
ipv6_update_v4.path_attr = [
    origin,               # 1. ORIGIN (mandatory)
    as_path_attr,         # 2. AS_PATH (mandatory) 
    med_attr,             # 4. MED (optional)
    local_pref_attr,      # 5. LOCAL_PREF (optional)
    atomic_aggr_attr,     # 6. ATOMIC_AGGREGATE (if present)
    aggregator_attr,      # 7. AGGREGATOR (if present)
    communities_attr,     # 10. COMMUNITIES (if present)
    ext_communities_attr, # 11. EXTENDED COMMUNITIES (if present)
    mp_reach_attr_v4      # 12. MP_REACH_NLRI (always last)
]

# Send IPv6 UPDATE over IPv4 session
ipv6_update_pkt_v4 = Ether(src=src_mac, dst=dst_mac)/IP(src=src_ipv4, dst=dst_ipv4, ttl=1, flags="DF", tos=0xC0, id=src_ip_id+5)/TCP(sport=sport, dport=dport, flags="PA", seq=seq_a_v4, ack=seq_b_v4, window=16384)/ipv6_update_v4
if len(ipv6_update_pkt_v4) < 60:
    pad_len = 60 - len(ipv6_update_pkt_v4)
    ipv6_update_pkt_v4 = ipv6_update_pkt_v4/Padding(load=b'\x00' * pad_len)
pkts.append(ipv6_update_pkt_v4)
seq_a_v4 += len(ipv6_update_v4)

# ACK for both updates from dst over IPv4
ack_both_pkt_v4 = Ether(src=dst_mac, dst=src_mac)/IP(src=dst_ipv4, dst=src_ipv4, ttl=1, flags=0, tos=0xC0, id=dst_ip_id+3)/TCP(sport=dport, dport=sport, flags="A", seq=seq_b_v4, ack=seq_a_v4, window=16384)
if len(ack_both_pkt_v4) < 60:
    pad_len = 60 - len(ack_both_pkt_v4)
    ack_both_pkt_v4 = ack_both_pkt_v4/Padding(load=b'\x00' * pad_len)
pkts.append(ack_both_pkt_v4)

# ======================================
# PART 2: BGP Session over IPv6 transport
# ======================================
print("[+] Generating BGP session over IPv6 transport...")

# TCP 3-way handshake for IPv6 session
seq_a_v6 = 2000  # Different initial sequence numbers
seq_b_v6 = 6000  # to distinguish from IPv4 session

# SYN packet - Src to Dst (Client to BGP Server)
syn_pkt_v6 = Ether(src=src_mac, dst=dst_mac)/IPv6(src=src_ipv6, dst=dst_ipv6, hlim=64)/TCP(sport=sport+1, dport=dport, flags="S", seq=seq_a_v6, window=16384, options=tcp_options)
if len(syn_pkt_v6) < 60:
    pad_len = 60 - len(syn_pkt_v6)
    syn_pkt_v6 = syn_pkt_v6/Padding(load=b'\x00' * pad_len)
pkts.append(syn_pkt_v6)

# SYN-ACK packet - Dst to Src (BGP Server to Client)
synack_pkt_v6 = Ether(src=dst_mac, dst=src_mac)/IPv6(src=dst_ipv6, dst=src_ipv6, hlim=64)/TCP(sport=dport, dport=sport+1, flags="SA", seq=seq_b_v6, ack=seq_a_v6+1, window=16384, options=tcp_options)
if len(synack_pkt_v6) < 60:
    pad_len = 60 - len(synack_pkt_v6)
    synack_pkt_v6 = synack_pkt_v6/Padding(load=b'\x00' * pad_len)
pkts.append(synack_pkt_v6)

# ACK packet - Src to Dst
ack_pkt_v6 = Ether(src=src_mac, dst=dst_mac)/IPv6(src=src_ipv6, dst=dst_ipv6, hlim=64)/TCP(sport=sport+1, dport=dport, flags="A", seq=seq_a_v6+1, ack=seq_b_v6+1, window=16384)
if len(ack_pkt_v6) < 60:
    pad_len = 60 - len(ack_pkt_v6)
    ack_pkt_v6 = ack_pkt_v6/Padding(load=b'\x00' * pad_len)
pkts.append(ack_pkt_v6)

# Create BGP OPEN message with capabilities for IPv6 session
open_a_v6 = BGPHeader(type=1)/BGPOpen(
    version=4, 
    my_as=src_as, 
    hold_time=180,
    bgp_id="1.1.1.1",  # BGP ID is always IPv4 format even in IPv6 sessions
    opt_param_len=None,
    opt_params=opt_params_src
)

# Send OPEN over IPv6
open_a_pkt_v6 = Ether(src=src_mac, dst=dst_mac)/IPv6(src=src_ipv6, dst=dst_ipv6, hlim=64)/TCP(sport=sport+1, dport=dport, flags="PA", seq=ack_pkt_v6[TCP].seq, ack=ack_pkt_v6[TCP].ack, window=16384)/open_a_v6
if len(open_a_pkt_v6) < 60:
    pad_len = 60 - len(open_a_pkt_v6)
    open_a_pkt_v6 = open_a_pkt_v6/Padding(load=b'\x00' * pad_len)
pkts.append(open_a_pkt_v6)
seq_a_v6 += len(open_a_v6)

# BGP OPEN from dst over IPv6
open_b_v6 = BGPHeader(type=1)/BGPOpen(
    version=4, 
    my_as=dst_as, 
    hold_time=180,
    bgp_id="2.2.2.2",
    opt_param_len=None,
    opt_params=opt_params_dst
)

open_b_pkt_v6 = Ether(src=dst_mac, dst=src_mac)/IPv6(src=dst_ipv6, dst=src_ipv6, hlim=64)/TCP(sport=dport, dport=sport+1, flags="PA", seq=synack_pkt_v6[TCP].seq+1, ack=seq_a_v6, window=16384)/open_b_v6
if len(open_b_pkt_v6) < 60:
    pad_len = 60 - len(open_b_pkt_v6)
    open_b_pkt_v6 = open_b_pkt_v6/Padding(load=b'\x00' * pad_len)
pkts.append(open_b_pkt_v6)
seq_b_v6 += len(open_b_v6)

# KEEPALIVE from src over IPv6
keep_a_v6 = BGPKeepAlive()
keep_a_pkt_v6 = Ether(src=src_mac, dst=dst_mac)/IPv6(src=src_ipv6, dst=dst_ipv6, hlim=64)/TCP(sport=sport+1, dport=dport, flags="PA", seq=seq_a_v6, ack=seq_b_v6, window=16384)/keep_a_v6
if len(keep_a_pkt_v6) < 60:
    pad_len = 60 - len(keep_a_pkt_v6)
    keep_a_pkt_v6 = keep_a_pkt_v6/Padding(load=b'\x00' * pad_len)
pkts.append(keep_a_pkt_v6)
seq_a_v6 += len(keep_a_v6)  

# KEEPALIVE from dst over IPv6
keep_b_v6 = BGPKeepAlive()
keep_b_pkt_v6 = Ether(src=dst_mac, dst=src_mac)/IPv6(src=dst_ipv6, dst=src_ipv6, hlim=64)/TCP(sport=dport, dport=sport+1, flags="PA", seq=seq_b_v6, ack=seq_a_v6, window=16384)/keep_b_v6
if len(keep_b_pkt_v6) < 60:
    pad_len = 60 - len(keep_b_pkt_v6)
    keep_b_pkt_v6 = keep_b_pkt_v6/Padding(load=b'\x00' * pad_len)
pkts.append(keep_b_pkt_v6)
seq_b_v6 += len(keep_b_v6)

# IPv6 advertisement directly in MP_REACH_NLRI over IPv6 transport
ipv6_update_v6 = BGPHeader(type=2)/BGPUpdate()

# MP_REACH_NLRI attribute for IPv6 over IPv6
mp_reach_attr_v6 = BGPPathAttr(type_flags=0x80, type_code=14)

# Create the MP_REACH_NLRI attribute for IPv6 session
mp_reach_v6 = BGPPAMPReachNLRI(
    afi=2,                # IPv6 = 2
    safi=1,               # Unicast = 1
    nh_addr_len=16,       # IPv6 address length
    nh_v6_addr=ipv6_next_hop,
    reserved=0,
    nlri=ipv6_nlri_objs   # Same IPv6 prefixes as before
)

mp_reach_attr_v6.attribute = mp_reach_v6

# Combine path attributes for IPv6 update over IPv6 session (following typical order)
ipv6_update_v6.path_attr = [
    origin,               # 1. ORIGIN (mandatory)
    as_path_attr,         # 2. AS_PATH (mandatory) 
    med_attr,             # 4. MED (optional)
    local_pref_attr,      # 5. LOCAL_PREF (optional)
    atomic_aggr_attr,     # 6. ATOMIC_AGGREGATE (if present)
    aggregator_attr,      # 7. AGGREGATOR (if present)
    communities_attr,     # 10. COMMUNITIES (if present)
    ext_communities_attr, # 11. EXTENDED COMMUNITIES (if present)
    mp_reach_attr_v6      # 12. MP_REACH_NLRI (always last)
]

# Send IPv6 UPDATE over IPv6 session
ipv6_update_pkt_v6 = Ether(src=src_mac, dst=dst_mac)/IPv6(src=src_ipv6, dst=dst_ipv6, hlim=64)/TCP(sport=sport+1, dport=dport, flags="PA", seq=seq_a_v6, ack=seq_b_v6, window=16384)/ipv6_update_v6
if len(ipv6_update_pkt_v6) < 60:
    pad_len = 60 - len(ipv6_update_pkt_v6)
    ipv6_update_pkt_v6 = ipv6_update_pkt_v6/Padding(load=b'\x00' * pad_len)
pkts.append(ipv6_update_pkt_v6)
seq_a_v6 += len(ipv6_update_v6)

# IPv4 advertisement via MP_REACH_NLRI over IPv6 transport
ipv4_update_v6 = BGPHeader(type=2)/BGPUpdate()

# MP_REACH_NLRI attribute for IPv4 over IPv6
mp_reach_ipv4_attr = BGPPathAttr(type_flags=0x80, type_code=14)

# Prepare IPv4 prefixes for MP_REACH_NLRI
ipv4_nlri_objs = []
for prefix in ipv4_nlri:
    ipv4_nlri_objs.append(BGPNLRI_IPv4(prefix=prefix))

# Create the MP_REACH_NLRI attribute for IPv4 over IPv6
mp_reach_ipv4 = BGPPAMPReachNLRI(
    afi=1,                # IPv4 = 1
    safi=1,               # Unicast = 1
    nh_addr_len=4,        # IPv4 address length
    nh_v4_addr=ipv4_next_hop,
    reserved=0,
    nlri=ipv4_nlri_objs
)

mp_reach_ipv4_attr.attribute = mp_reach_ipv4

# Combine path attributes for IPv4 update over IPv6 session (following typical order)
ipv4_update_v6.path_attr = [
    origin,               # 1. ORIGIN (mandatory)
    as_path_attr,         # 2. AS_PATH (mandatory) 
    med_attr,             # 4. MED (optional)
    local_pref_attr,      # 5. LOCAL_PREF (optional)
    atomic_aggr_attr,     # 6. ATOMIC_AGGREGATE (if present)
    aggregator_attr,      # 7. AGGREGATOR (if present)
    communities_attr,     # 10. COMMUNITIES (if present)
    ext_communities_attr, # 11. EXTENDED COMMUNITIES (if present)
    mp_reach_ipv4_attr    # 12. MP_REACH_NLRI (always last)
]

# Send IPv4 UPDATE over IPv6 session
ipv4_update_pkt_v6 = Ether(src=src_mac, dst=dst_mac)/IPv6(src=src_ipv6, dst=dst_ipv6, hlim=64)/TCP(sport=sport+1, dport=dport, flags="PA", seq=seq_a_v6, ack=seq_b_v6, window=16384)/ipv4_update_v6
if len(ipv4_update_pkt_v6) < 60:
    pad_len = 60 - len(ipv4_update_pkt_v6)
    ipv4_update_pkt_v6 = ipv4_update_pkt_v6/Padding(load=b'\x00' * pad_len)
pkts.append(ipv4_update_pkt_v6)
seq_a_v6 += len(ipv4_update_v6)

# ACK for both updates from dst over IPv6
ack_both_pkt_v6 = Ether(src=dst_mac, dst=src_mac)/IPv6(src=dst_ipv6, dst=src_ipv6, hlim=64)/TCP(sport=dport, dport=sport+1, flags="A", seq=seq_b_v6, ack=seq_a_v6, window=16384)
if len(ack_both_pkt_v6) < 60:
    pad_len = 60 - len(ack_both_pkt_v6)
    ack_both_pkt_v6 = ack_both_pkt_v6/Padding(load=b'\x00' * pad_len)
pkts.append(ack_both_pkt_v6)

# Create pcaps directory if it doesn't exist
os.makedirs("pcaps", exist_ok=True)

# Write to pcap
wrpcap("pcaps/realistic_bgp.pcap", pkts)
print("✅ Wrote pcaps/realistic_bgp.pcap with fully realistic BGP traffic")