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

# ======================================
# PART 3: Realistic BGP Update Scenarios
# ======================================
print("[+] Generating realistic BGP updates for IPv4 session...")

# ------------ Scenario 1: ORIGIN Change (IGP → INCOMPLETE → IGP) ------------
# IGP (0) → INCOMPLETE (2) ORIGIN change for first prefix
print("[*] Generating ORIGIN change scenario (IGP → INCOMPLETE → IGP)...")
origin_change_update = BGPHeader(type=2)/BGPUpdate()

# Create origin attribute with INCOMPLETE (2)
origin_incomplete = BGPPathAttr(type_flags=0x40, type_code=1)
origin_incomplete.attribute = BGPPAOrigin(origin=2)  # INCOMPLETE = 2

# Use same prefix but with changed ORIGIN
origin_change_update.path_attr = [
    origin_incomplete,    # Changed from IGP (0) to INCOMPLETE (2)
    as_path_attr,
    next_hop_attr_v4,
    med_attr,
    local_pref_attr,
    communities_attr,
]

origin_change_update.nlri.append(BGPNLRI_IPv4(prefix=ipv4_nlri[0]))

# Send ORIGIN change update over IPv4
origin_change_pkt = Ether(src=src_mac, dst=dst_mac)/IP(src=src_ipv4, dst=dst_ipv4, ttl=1, flags="DF", tos=0xC0, id=src_ip_id+6)/TCP(sport=sport, dport=dport, flags="PA", seq=seq_a_v4, ack=seq_b_v4, window=16384)/origin_change_update
if len(origin_change_pkt) < 60:
    pad_len = 60 - len(origin_change_pkt)
    origin_change_pkt = origin_change_pkt/Padding(load=b'\x00' * pad_len)
pkts.append(origin_change_pkt)
seq_a_v4 += len(origin_change_update)

# ACK for ORIGIN change
origin_change_ack = Ether(src=dst_mac, dst=src_mac)/IP(src=dst_ipv4, dst=src_ipv4, ttl=1, flags=0, tos=0xC0, id=dst_ip_id+4)/TCP(sport=dport, dport=sport, flags="A", seq=seq_b_v4, ack=seq_a_v4, window=16384)
if len(origin_change_ack) < 60:
    pad_len = 60 - len(origin_change_ack)
    origin_change_ack = origin_change_ack/Padding(load=b'\x00' * pad_len)
pkts.append(origin_change_ack)

# Change back to IGP (0)
origin_igp_update = BGPHeader(type=2)/BGPUpdate()

# Create origin attribute with IGP (0)
origin_igp = BGPPathAttr(type_flags=0x40, type_code=1)
origin_igp.attribute = BGPPAOrigin(origin=0)  # IGP = 0

# Use same prefix with IGP origin
origin_igp_update.path_attr = [
    origin_igp,           # Changed back from INCOMPLETE (2) to IGP (0)
    as_path_attr,
    next_hop_attr_v4,
    med_attr,
    local_pref_attr,
    communities_attr,
]

origin_igp_update.nlri.append(BGPNLRI_IPv4(prefix=ipv4_nlri[0]))

# Send IGP ORIGIN change over IPv4
origin_igp_pkt = Ether(src=src_mac, dst=dst_mac)/IP(src=src_ipv4, dst=dst_ipv4, ttl=1, flags="DF", tos=0xC0, id=src_ip_id+7)/TCP(sport=sport, dport=dport, flags="PA", seq=seq_a_v4, ack=seq_b_v4, window=16384)/origin_igp_update
if len(origin_igp_pkt) < 60:
    pad_len = 60 - len(origin_igp_pkt)
    origin_igp_pkt = origin_igp_pkt/Padding(load=b'\x00' * pad_len)
pkts.append(origin_igp_pkt)
seq_a_v4 += len(origin_igp_update)

# ACK for IGP ORIGIN change
origin_igp_ack = Ether(src=dst_mac, dst=src_mac)/IP(src=dst_ipv4, dst=src_ipv4, ttl=1, flags=0, tos=0xC0, id=dst_ip_id+5)/TCP(sport=dport, dport=sport, flags="A", seq=seq_b_v4, ack=seq_a_v4, window=16384)
if len(origin_igp_ack) < 60:
    pad_len = 60 - len(origin_igp_ack)
    origin_igp_ack = origin_igp_ack/Padding(load=b'\x00' * pad_len)
pkts.append(origin_igp_ack)

# ------------ Scenario 2: AS_PATH Modifications (Path Prepending) ------------
# Create update with AS path prepending
as_path_prepend_update = BGPHeader(type=2)/BGPUpdate()

# Create a new AS_PATH with prepending
as_path_prepend_attr = BGPPathAttr(type_flags=0x40, type_code=2)

# Create the prepended AS_PATH segment
as_path_prepend_segment = BGPPAASPath()
# Create a segment with prepended AS values
prepend_segment = BGPPAASPath.ASPathSegment(
    segment_type=2,  # AS_SEQUENCE
    segment_length=3,
    segment_value=[src_as, src_as, src_as]  # Prepend own AS 3 times
)
# Add the segment to the AS_PATH
as_path_prepend_segment.segments = [prepend_segment]
as_path_prepend_attr.attribute = as_path_prepend_segment

# Use the prepended AS_PATH with a prefix
as_path_prepend_update.path_attr = [
    origin,               # Back to IGP origin
    as_path_prepend_attr, # Prepended AS_PATH
    next_hop_attr_v4,
    med_attr,
    local_pref_attr,
    communities_attr,
]

# Add a prefix to the update
as_path_prepend_update.nlri.append(BGPNLRI_IPv4(prefix="192.0.2.0/24"))  # Different prefix

# Send AS_PATH prepending update
as_path_prepend_pkt = Ether(src=src_mac, dst=dst_mac)/IP(src=src_ipv4, dst=dst_ipv4, ttl=1, flags="DF", tos=0xC0, id=src_ip_id+8)/TCP(sport=sport, dport=dport, flags="PA", seq=seq_a_v4, ack=seq_b_v4, window=16384)/as_path_prepend_update
if len(as_path_prepend_pkt) < 60:
    pad_len = 60 - len(as_path_prepend_pkt)
    as_path_prepend_pkt = as_path_prepend_pkt/Padding(load=b'\x00' * pad_len)
pkts.append(as_path_prepend_pkt)
seq_a_v4 += len(as_path_prepend_update)

# ACK for AS_PATH prepending
as_path_prepend_ack = Ether(src=dst_mac, dst=src_mac)/IP(src=dst_ipv4, dst=src_ipv4, ttl=1, flags=0, tos=0xC0, id=dst_ip_id+6)/TCP(sport=dport, dport=sport, flags="A", seq=seq_b_v4, ack=seq_a_v4, window=16384)
if len(as_path_prepend_ack) < 60:
    pad_len = 60 - len(as_path_prepend_ack)
    as_path_prepend_ack = as_path_prepend_ack/Padding(load=b'\x00' * pad_len)
pkts.append(as_path_prepend_ack)

# Create update with complex AS_PATH (including AS_SET)
as_path_complex_update = BGPHeader(type=2)/BGPUpdate()

# Create a complex AS_PATH with both AS_SEQUENCE and AS_SET
as_path_complex_attr = BGPPathAttr(type_flags=0x40, type_code=2)

# Create the complex AS_PATH segment
as_path_complex_segment = BGPPAASPath()

# Create an AS_SEQUENCE segment
sequence_segment = BGPPAASPath.ASPathSegment(
    segment_type=2,  # AS_SEQUENCE
    segment_length=2,
    segment_value=[src_as, 65100]  # Add a transit AS
)

# Create an AS_SET segment (for aggregated routes)
set_segment = BGPPAASPath.ASPathSegment(
    segment_type=1,  # AS_SET
    segment_length=3,
    segment_value=[65200, 65201, 65202]  # Multiple origin ASes in a set
)

# Add both segments to the AS_PATH
as_path_complex_segment.segments = [sequence_segment, set_segment]
as_path_complex_attr.attribute = as_path_complex_segment

# Use the complex AS_PATH with a prefix
as_path_complex_update.path_attr = [
    origin,               # IGP origin
    as_path_complex_attr, # Complex AS_PATH with AS_SET
    next_hop_attr_v4,
    med_attr,
    local_pref_attr,
    atomic_aggr_attr,     # This is an aggregated route
    aggregator_attr,      # Include aggregator info
    communities_attr,
]

# Add a prefix to the update
as_path_complex_update.nlri.append(BGPNLRI_IPv4(prefix="192.0.2.0/23"))  # Aggregated prefix

# Send complex AS_PATH update
as_path_complex_pkt = Ether(src=src_mac, dst=dst_mac)/IP(src=src_ipv4, dst=dst_ipv4, ttl=1, flags="DF", tos=0xC0, id=src_ip_id+9)/TCP(sport=sport, dport=dport, flags="PA", seq=seq_a_v4, ack=seq_b_v4, window=16384)/as_path_complex_update
if len(as_path_complex_pkt) < 60:
    pad_len = 60 - len(as_path_complex_pkt)
    as_path_complex_pkt = as_path_complex_pkt/Padding(load=b'\x00' * pad_len)
pkts.append(as_path_complex_pkt)
seq_a_v4 += len(as_path_complex_update)

# ACK for complex AS_PATH
as_path_complex_ack = Ether(src=dst_mac, dst=src_mac)/IP(src=dst_ipv4, dst=src_ipv4, ttl=1, flags=0, tos=0xC0, id=dst_ip_id+7)/TCP(sport=dport, dport=sport, flags="A", seq=seq_b_v4, ack=seq_a_v4, window=16384)
if len(as_path_complex_ack) < 60:
    pad_len = 60 - len(as_path_complex_ack)
    as_path_complex_ack = as_path_complex_ack/Padding(load=b'\x00' * pad_len)
pkts.append(as_path_complex_ack)

# ------------ Scenario 3: NEXT_HOP Changes ------------
# Create update with changed next hop
next_hop_change_update = BGPHeader(type=2)/BGPUpdate()

# Create next hop attribute with a different next hop
changed_next_hop = "10.0.0.100"  # New next hop
next_hop_change_attr = BGPPathAttr(type_flags=0x40, type_code=3)
next_hop_change_attr.attribute = BGPPANextHop(next_hop=changed_next_hop)

# Use the changed next hop with the same prefix
next_hop_change_update.path_attr = [
    origin,               # IGP origin
    as_path_attr,         # Normal AS path
    next_hop_change_attr, # Changed next hop
    med_attr,
    local_pref_attr,
]

# Add a prefix to the update
next_hop_change_update.nlri.append(BGPNLRI_IPv4(prefix=ipv4_nlri[0]))

# Send next hop change update
next_hop_change_pkt = Ether(src=src_mac, dst=dst_mac)/IP(src=src_ipv4, dst=dst_ipv4, ttl=1, flags="DF", tos=0xC0, id=src_ip_id+10)/TCP(sport=sport, dport=dport, flags="PA", seq=seq_a_v4, ack=seq_b_v4, window=16384)/next_hop_change_update
if len(next_hop_change_pkt) < 60:
    pad_len = 60 - len(next_hop_change_pkt)
    next_hop_change_pkt = next_hop_change_pkt/Padding(load=b'\x00' * pad_len)
pkts.append(next_hop_change_pkt)
seq_a_v4 += len(next_hop_change_update)

# ACK for next hop change
next_hop_change_ack = Ether(src=dst_mac, dst=src_mac)/IP(src=dst_ipv4, dst=src_ipv4, ttl=1, flags=0, tos=0xC0, id=dst_ip_id+8)/TCP(sport=dport, dport=sport, flags="A", seq=seq_b_v4, ack=seq_a_v4, window=16384)
if len(next_hop_change_ack) < 60:
    pad_len = 60 - len(next_hop_change_ack)
    next_hop_change_ack = next_hop_change_ack/Padding(load=b'\x00' * pad_len)
pkts.append(next_hop_change_ack)

# ------------ Scenario 4: MED Value Adjustments ------------
# Create update with changed MED value
med_change_update = BGPHeader(type=2)/BGPUpdate()

# Create MED attribute with a different value
med_change_attr = BGPPathAttr(type_flags=0x80, type_code=4)
med_change_attr.attribute = BGPPAMultiExitDisc(med=50)  # Lower MED = more preferred

# Use the changed MED with the same prefix
med_change_update.path_attr = [
    origin,               # IGP origin
    as_path_attr,         # Normal AS path
    next_hop_attr_v4,     # Original next hop
    med_change_attr,      # Changed MED
    local_pref_attr,
    communities_attr,
]

# Add a prefix to the update
med_change_update.nlri.append(BGPNLRI_IPv4(prefix=ipv4_nlri[1]))

# Send MED change update
med_change_pkt = Ether(src=src_mac, dst=dst_mac)/IP(src=src_ipv4, dst=dst_ipv4, ttl=1, flags="DF", tos=0xC0, id=src_ip_id+11)/TCP(sport=sport, dport=dport, flags="PA", seq=seq_a_v4, ack=seq_b_v4, window=16384)/med_change_update
if len(med_change_pkt) < 60:
    pad_len = 60 - len(med_change_pkt)
    med_change_pkt = med_change_pkt/Padding(load=b'\x00' * pad_len)
pkts.append(med_change_pkt)
seq_a_v4 += len(med_change_update)

# ACK for MED change
med_change_ack = Ether(src=dst_mac, dst=src_mac)/IP(src=dst_ipv4, dst=src_ipv4, ttl=1, flags=0, tos=0xC0, id=dst_ip_id+9)/TCP(sport=dport, dport=sport, flags="A", seq=seq_b_v4, ack=seq_a_v4, window=16384)
if len(med_change_ack) < 60:
    pad_len = 60 - len(med_change_ack)
    med_change_ack = med_change_ack/Padding(load=b'\x00' * pad_len)
pkts.append(med_change_ack)

# ------------ Scenario 5: LOCAL_PREF Modifications ------------
# Create update with changed LOCAL_PREF
local_pref_change_update = BGPHeader(type=2)/BGPUpdate()

# Create LOCAL_PREF attribute with a different value
local_pref_change_attr = BGPPathAttr(type_flags=0x40, type_code=5)
local_pref_change_attr.attribute = BGPPALocalPref(local_pref=300)  # Higher LOCAL_PREF = more preferred

# Use the changed LOCAL_PREF with the same prefix
local_pref_change_update.path_attr = [
    origin,               # IGP origin
    as_path_attr,         # Normal AS path
    next_hop_attr_v4,     # Original next hop
    med_attr,             # Original MED
    local_pref_change_attr, # Changed LOCAL_PREF
    communities_attr,
]

# Add a prefix to the update
local_pref_change_update.nlri.append(BGPNLRI_IPv4(prefix=ipv4_nlri[1]))

# Send LOCAL_PREF change update
local_pref_change_pkt = Ether(src=src_mac, dst=dst_mac)/IP(src=src_ipv4, dst=dst_ipv4, ttl=1, flags="DF", tos=0xC0, id=src_ip_id+12)/TCP(sport=sport, dport=dport, flags="PA", seq=seq_a_v4, ack=seq_b_v4, window=16384)/local_pref_change_update
if len(local_pref_change_pkt) < 60:
    pad_len = 60 - len(local_pref_change_pkt)
    local_pref_change_pkt = local_pref_change_pkt/Padding(load=b'\x00' * pad_len)
pkts.append(local_pref_change_pkt)
seq_a_v4 += len(local_pref_change_update)

# ACK for LOCAL_PREF change
local_pref_change_ack = Ether(src=dst_mac, dst=src_mac)/IP(src=dst_ipv4, dst=src_ipv4, ttl=1, flags=0, tos=0xC0, id=dst_ip_id+10)/TCP(sport=dport, dport=sport, flags="A", seq=seq_b_v4, ack=seq_a_v4, window=16384)
if len(local_pref_change_ack) < 60:
    pad_len = 60 - len(local_pref_change_ack)
    local_pref_change_ack = local_pref_change_ack/Padding(load=b'\x00' * pad_len)
pkts.append(local_pref_change_ack)

# ------------ Scenario 6: Community Changes ------------
# Create update with changed communities
communities_change_update = BGPHeader(type=2)/BGPUpdate()

# Create a new communities list
new_communities_list = []
# Add some well-known communities
new_communities_list.append(BGPPACommunity(community=0xFFFFFF02))  # NO_ADVERTISE
new_communities_list.append(BGPPACommunity(community=0xFFFFFF03))  # NO_EXPORT_SUBCONFED
# Add a custom community
new_communities_list.append(BGPPACommunity(community=src_as<<16|300))  # src_as:300

# Create the new communities path attribute
new_communities_attr = BGPPathAttr(type_flags=0x40|0x80, type_code=8)
new_communities_attr.attribute = new_communities_list

# Use the changed communities with the same prefix
communities_change_update.path_attr = [
    origin,               # IGP origin
    as_path_attr,         # Normal AS path
    next_hop_attr_v4,     # Original next hop
    med_attr,             # Original MED
    local_pref_attr,      # Original LOCAL_PREF
    new_communities_attr, # Changed communities
]

# Add a prefix to the update
communities_change_update.nlri.append(BGPNLRI_IPv4(prefix="192.0.2.0/24"))

# Send communities change update
communities_change_pkt = Ether(src=src_mac, dst=dst_mac)/IP(src=src_ipv4, dst=dst_ipv4, ttl=1, flags="DF", tos=0xC0, id=src_ip_id+13)/TCP(sport=sport, dport=dport, flags="PA", seq=seq_a_v4, ack=seq_b_v4, window=16384)/communities_change_update
if len(communities_change_pkt) < 60:
    pad_len = 60 - len(communities_change_pkt)
    communities_change_pkt = communities_change_pkt/Padding(load=b'\x00' * pad_len)
pkts.append(communities_change_pkt)
seq_a_v4 += len(communities_change_update)

# ACK for communities change
communities_change_ack = Ether(src=dst_mac, dst=src_mac)/IP(src=dst_ipv4, dst=src_ipv4, ttl=1, flags=0, tos=0xC0, id=dst_ip_id+11)/TCP(sport=dport, dport=sport, flags="A", seq=seq_b_v4, ack=seq_a_v4, window=16384)
if len(communities_change_ack) < 60:
    pad_len = 60 - len(communities_change_ack)
    communities_change_ack = communities_change_ack/Padding(load=b'\x00' * pad_len)
pkts.append(communities_change_ack)

# ------------ Scenario 7: Route Flapping ------------
# Simulate route flapping with multiple withdrawals and re-announcements
flap_prefix = "203.0.113.128/25"

# First announcement of the flapping prefix
flap_announce_1 = BGPHeader(type=2)/BGPUpdate()
flap_announce_1.path_attr = [
    origin,
    as_path_attr,
    next_hop_attr_v4,
    med_attr,
    local_pref_attr,
]
flap_announce_1.nlri.append(BGPNLRI_IPv4(prefix=flap_prefix))

# Send first announcement
flap_announce_1_pkt = Ether(src=src_mac, dst=dst_mac)/IP(src=src_ipv4, dst=dst_ipv4, ttl=1, flags="DF", tos=0xC0, id=src_ip_id+14)/TCP(sport=sport, dport=dport, flags="PA", seq=seq_a_v4, ack=seq_b_v4, window=16384)/flap_announce_1
if len(flap_announce_1_pkt) < 60:
    pad_len = 60 - len(flap_announce_1_pkt)
    flap_announce_1_pkt = flap_announce_1_pkt/Padding(load=b'\x00' * pad_len)
pkts.append(flap_announce_1_pkt)
seq_a_v4 += len(flap_announce_1)

# ACK for first announcement
flap_announce_1_ack = Ether(src=dst_mac, dst=src_mac)/IP(src=dst_ipv4, dst=src_ipv4, ttl=1, flags=0, tos=0xC0, id=dst_ip_id+12)/TCP(sport=dport, dport=sport, flags="A", seq=seq_b_v4, ack=seq_a_v4, window=16384)
if len(flap_announce_1_ack) < 60:
    pad_len = 60 - len(flap_announce_1_ack)
    flap_announce_1_ack = flap_announce_1_ack/Padding(load=b'\x00' * pad_len)
pkts.append(flap_announce_1_ack)

# First withdrawal of the flapping prefix
flap_withdraw_1 = BGPHeader(type=2)/BGPUpdate()
flap_withdraw_1.withdrawn = [BGPNLRI_IPv4(prefix=flap_prefix)]

# Send first withdrawal
flap_withdraw_1_pkt = Ether(src=src_mac, dst=dst_mac)/IP(src=src_ipv4, dst=dst_ipv4, ttl=1, flags="DF", tos=0xC0, id=src_ip_id+15)/TCP(sport=sport, dport=dport, flags="PA", seq=seq_a_v4, ack=seq_b_v4, window=16384)/flap_withdraw_1
if len(flap_withdraw_1_pkt) < 60:
    pad_len = 60 - len(flap_withdraw_1_pkt)
    flap_withdraw_1_pkt = flap_withdraw_1_pkt/Padding(load=b'\x00' * pad_len)
pkts.append(flap_withdraw_1_pkt)
seq_a_v4 += len(flap_withdraw_1)

# ACK for first withdrawal
flap_withdraw_1_ack = Ether(src=dst_mac, dst=src_mac)/IP(src=dst_ipv4, dst=src_ipv4, ttl=1, flags=0, tos=0xC0, id=dst_ip_id+13)/TCP(sport=dport, dport=sport, flags="A", seq=seq_b_v4, ack=seq_a_v4, window=16384)
if len(flap_withdraw_1_ack) < 60:
    pad_len = 60 - len(flap_withdraw_1_ack)
    flap_withdraw_1_ack = flap_withdraw_1_ack/Padding(load=b'\x00' * pad_len)
pkts.append(flap_withdraw_1_ack)

# Second announcement of the flapping prefix
flap_announce_2 = BGPHeader(type=2)/BGPUpdate()
flap_announce_2.path_attr = [
    origin,
    as_path_attr,
    next_hop_attr_v4,
    med_attr,
    local_pref_attr,
]
flap_announce_2.nlri.append(BGPNLRI_IPv4(prefix=flap_prefix))

# Send second announcement
flap_announce_2_pkt = Ether(src=src_mac, dst=dst_mac)/IP(src=src_ipv4, dst=dst_ipv4, ttl=1, flags="DF", tos=0xC0, id=src_ip_id+16)/TCP(sport=sport, dport=dport, flags="PA", seq=seq_a_v4, ack=seq_b_v4, window=16384)/flap_announce_2
if len(flap_announce_2_pkt) < 60:
    pad_len = 60 - len(flap_announce_2_pkt)
    flap_announce_2_pkt = flap_announce_2_pkt/Padding(load=b'\x00' * pad_len)
pkts.append(flap_announce_2_pkt)
seq_a_v4 += len(flap_announce_2)

# ACK for second announcement
flap_announce_2_ack = Ether(src=dst_mac, dst=src_mac)/IP(src=dst_ipv4, dst=src_ipv4, ttl=1, flags=0, tos=0xC0, id=dst_ip_id+14)/TCP(sport=dport, dport=sport, flags="A", seq=seq_b_v4, ack=seq_a_v4, window=16384)
if len(flap_announce_2_ack) < 60:
    pad_len = 60 - len(flap_announce_2_ack)
    flap_announce_2_ack = flap_announce_2_ack/Padding(load=b'\x00' * pad_len)
pkts.append(flap_announce_2_ack)

# Second withdrawal of the flapping prefix
flap_withdraw_2 = BGPHeader(type=2)/BGPUpdate()
flap_withdraw_2.withdrawn = [BGPNLRI_IPv4(prefix=flap_prefix)]

# Send second withdrawal
flap_withdraw_2_pkt = Ether(src=src_mac, dst=dst_mac)/IP(src=src_ipv4, dst=dst_ipv4, ttl=1, flags="DF", tos=0xC0, id=src_ip_id+17)/TCP(sport=sport, dport=dport, flags="PA", seq=seq_a_v4, ack=seq_b_v4, window=16384)/flap_withdraw_2
if len(flap_withdraw_2_pkt) < 60:
    pad_len = 60 - len(flap_withdraw_2_pkt)
    flap_withdraw_2_pkt = flap_withdraw_2_pkt/Padding(load=b'\x00' * pad_len)
pkts.append(flap_withdraw_2_pkt)
seq_a_v4 += len(flap_withdraw_2)

# ACK for second withdrawal
flap_withdraw_2_ack = Ether(src=dst_mac, dst=src_mac)/IP(src=dst_ipv4, dst=src_ipv4, ttl=1, flags=0, tos=0xC0, id=dst_ip_id+15)/TCP(sport=dport, dport=sport, flags="A", seq=seq_b_v4, ack=seq_a_v4, window=16384)
if len(flap_withdraw_2_ack) < 60:
    pad_len = 60 - len(flap_withdraw_2_ack)
    flap_withdraw_2_ack = flap_withdraw_2_ack/Padding(load=b'\x00' * pad_len)
pkts.append(flap_withdraw_2_ack)

# ------------ Scenario 8: Dampened Routes ------------
# Create a route suppression message due to dampening
dampen_message_update = BGPHeader(type=2)/BGPUpdate()

# Add Graceful Shutdown community (GSHUT) to indicate dampening
dampen_communities_list = []
dampen_communities_list.append(BGPPACommunity(community=0xFFFF0002))  # GSHUT community
dampen_communities_list.append(BGPPACommunity(community=0xFFFF0004))  # DampInfo community (custom)

dampen_communities_attr = BGPPathAttr(type_flags=0x40|0x80, type_code=8)
dampen_communities_attr.attribute = dampen_communities_list

# Create update message for dampened route
dampen_message_update.path_attr = [
    origin,
    as_path_attr,
    next_hop_attr_v4,
    med_attr,
    local_pref_attr,
    dampen_communities_attr,
]

# Add the previously flapping prefix
dampen_message_update.nlri.append(BGPNLRI_IPv4(prefix=flap_prefix))

# Send dampened route message
dampen_message_pkt = Ether(src=src_mac, dst=dst_mac)/IP(src=src_ipv4, dst=dst_ipv4, ttl=1, flags="DF", tos=0xC0, id=src_ip_id+18)/TCP(sport=sport, dport=dport, flags="PA", seq=seq_a_v4, ack=seq_b_v4, window=16384)/dampen_message_update
if len(dampen_message_pkt) < 60:
    pad_len = 60 - len(dampen_message_pkt)
    dampen_message_pkt = dampen_message_pkt/Padding(load=b'\x00' * pad_len)
pkts.append(dampen_message_pkt)
seq_a_v4 += len(dampen_message_update)

# ACK for dampened route message
dampen_message_ack = Ether(src=dst_mac, dst=src_mac)/IP(src=dst_ipv4, dst=src_ipv4, ttl=1, flags=0, tos=0xC0, id=dst_ip_id+16)/TCP(sport=dport, dport=sport, flags="A", seq=seq_b_v4, ack=seq_a_v4, window=16384)
if len(dampen_message_ack) < 60:
    pad_len = 60 - len(dampen_message_ack)
    dampen_message_ack = dampen_message_ack/Padding(load=b'\x00' * pad_len)
pkts.append(dampen_message_ack)

# ------------ Scenario 9: Duplicate Announcements ------------
# Create duplicate announcement of the same prefix
dup_prefix = "198.51.100.0/24"  # Use existing prefix

# First announcement (already done in initial updates)
# Second identical announcement (duplicate)
duplicate_update = BGPHeader(type=2)/BGPUpdate()
duplicate_update.path_attr = [
    origin,
    as_path_attr,
    next_hop_attr_v4,
    med_attr,
    local_pref_attr,
    communities_attr,
]
duplicate_update.nlri.append(BGPNLRI_IPv4(prefix=dup_prefix))

# Send duplicate announcement
duplicate_pkt = Ether(src=src_mac, dst=dst_mac)/IP(src=src_ipv4, dst=dst_ipv4, ttl=1, flags="DF", tos=0xC0, id=src_ip_id+19)/TCP(sport=sport, dport=dport, flags="PA", seq=seq_a_v4, ack=seq_b_v4, window=16384)/duplicate_update
if len(duplicate_pkt) < 60:
    pad_len = 60 - len(duplicate_pkt)
    duplicate_pkt = duplicate_pkt/Padding(load=b'\x00' * pad_len)
pkts.append(duplicate_pkt)
seq_a_v4 += len(duplicate_update)

# ACK for duplicate announcement
duplicate_ack = Ether(src=dst_mac, dst=src_mac)/IP(src=dst_ipv4, dst=src_ipv4, ttl=1, flags=0, tos=0xC0, id=dst_ip_id+17)/TCP(sport=dport, dport=sport, flags="A", seq=seq_b_v4, ack=seq_a_v4, window=16384)
if len(duplicate_ack) < 60:
    pad_len = 60 - len(duplicate_ack)
    duplicate_ack = duplicate_ack/Padding(load=b'\x00' * pad_len)
pkts.append(duplicate_ack)

# ------------ Scenario 10: Import/Export Policy Changes ------------
# Withdrawal triggered by policy change
policy_withdraw_update = BGPHeader(type=2)/BGPUpdate()

# Withdraw multiple prefixes due to policy change
policy_withdraw_update.withdrawn = [
    BGPNLRI_IPv4(prefix="192.0.2.0/24"),
    BGPNLRI_IPv4(prefix="192.0.2.0/23")
]

# Send policy withdrawal
policy_withdraw_pkt = Ether(src=src_mac, dst=dst_mac)/IP(src=src_ipv4, dst=dst_ipv4, ttl=1, flags="DF", tos=0xC0, id=src_ip_id+20)/TCP(sport=sport, dport=dport, flags="PA", seq=seq_a_v4, ack=seq_b_v4, window=16384)/policy_withdraw_update
if len(policy_withdraw_pkt) < 60:
    pad_len = 60 - len(policy_withdraw_pkt)
    policy_withdraw_pkt = policy_withdraw_pkt/Padding(load=b'\x00' * pad_len)
pkts.append(policy_withdraw_pkt)
seq_a_v4 += len(policy_withdraw_update)

# ACK for policy withdrawal
policy_withdraw_ack = Ether(src=dst_mac, dst=src_mac)/IP(src=dst_ipv4, dst=src_ipv4, ttl=1, flags=0, tos=0xC0, id=dst_ip_id+18)/TCP(sport=dport, dport=sport, flags="A", seq=seq_b_v4, ack=seq_a_v4, window=16384)
if len(policy_withdraw_ack) < 60:
    pad_len = 60 - len(policy_withdraw_ack)
    policy_withdraw_ack = policy_withdraw_ack/Padding(load=b'\x00' * pad_len)
pkts.append(policy_withdraw_ack)

# ------------ Scenario 11: AS Path Length Changes ------------
# Create update with longer AS path (path length change)
as_path_length_update = BGPHeader(type=2)/BGPUpdate()

# Create an AS_PATH with increased length
as_path_length_attr = BGPPathAttr(type_flags=0x40, type_code=2)

# Create a longer AS_PATH segment
as_path_length_segment = BGPPAASPath()
# Create a segment with multiple ASes in path
length_segment = BGPPAASPath.ASPathSegment(
    segment_type=2,  # AS_SEQUENCE
    segment_length=5,
    segment_value=[src_as, 65100, 65200, 65300, 65400]  # Longer path through multiple ASes
)
# Add the segment to the AS_PATH
as_path_length_segment.segments = [length_segment]
as_path_length_attr.attribute = as_path_length_segment

# Use the longer AS_PATH with a new prefix
as_path_length_update.path_attr = [
    origin,
    as_path_length_attr,
    next_hop_attr_v4,
    med_attr,
    local_pref_attr,
]

# Add a prefix to the update
as_path_length_update.nlri.append(BGPNLRI_IPv4(prefix="198.51.100.128/25"))  # More specific prefix

# Send AS path length update
as_path_length_pkt = Ether(src=src_mac, dst=dst_mac)/IP(src=src_ipv4, dst=dst_ipv4, ttl=1, flags="DF", tos=0xC0, id=src_ip_id+21)/TCP(sport=sport, dport=dport, flags="PA", seq=seq_a_v4, ack=seq_b_v4, window=16384)/as_path_length_update
if len(as_path_length_pkt) < 60:
    pad_len = 60 - len(as_path_length_pkt)
    as_path_length_pkt = as_path_length_pkt/Padding(load=b'\x00' * pad_len)
pkts.append(as_path_length_pkt)
seq_a_v4 += len(as_path_length_update)

# ACK for AS path length update
as_path_length_ack = Ether(src=dst_mac, dst=src_mac)/IP(src=dst_ipv4, dst=src_ipv4, ttl=1, flags=0, tos=0xC0, id=dst_ip_id+19)/TCP(sport=dport, dport=sport, flags="A", seq=seq_b_v4, ack=seq_a_v4, window=16384)
if len(as_path_length_ack) < 60:
    pad_len = 60 - len(as_path_length_ack)
    as_path_length_ack = as_path_length_ack/Padding(load=b'\x00' * pad_len)
pkts.append(as_path_length_ack)

# ------------ Scenario 12: Route Aggregation/Summarization ------------
# Create update with aggregated routes
aggregation_update = BGPHeader(type=2)/BGPUpdate()

# Use attributes for route aggregation
aggregation_update.path_attr = [
    origin,
    as_path_attr,
    next_hop_attr_v4,
    med_attr,
    local_pref_attr,
    atomic_aggr_attr,     # Indicate route aggregation
    aggregator_attr,      # Provide aggregator info
]

# Add a prefix to the update (larger aggregate)
aggregation_update.nlri.append(BGPNLRI_IPv4(prefix="198.51.100.0/20"))  # Aggregate of multiple /24s

# Send aggregation update
aggregation_pkt = Ether(src=src_mac, dst=dst_mac)/IP(src=src_ipv4, dst=dst_ipv4, ttl=1, flags="DF", tos=0xC0, id=src_ip_id+22)/TCP(sport=sport, dport=dport, flags="PA", seq=seq_a_v4, ack=seq_b_v4, window=16384)/aggregation_update
if len(aggregation_pkt) < 60:
    pad_len = 60 - len(aggregation_pkt)
    aggregation_pkt = aggregation_pkt/Padding(load=b'\x00' * pad_len)
pkts.append(aggregation_pkt)
seq_a_v4 += len(aggregation_update)

# ACK for aggregation update
aggregation_ack = Ether(src=dst_mac, dst=src_mac)/IP(src=dst_ipv4, dst=src_ipv4, ttl=1, flags=0, tos=0xC0, id=dst_ip_id+20)/TCP(sport=dport, dport=sport, flags="A", seq=seq_b_v4, ack=seq_a_v4, window=16384)
if len(aggregation_ack) < 60:
    pad_len = 60 - len(aggregation_ack)
    aggregation_ack = aggregation_ack/Padding(load=b'\x00' * pad_len)
pkts.append(aggregation_ack)

# ------------ Scenario 13: iBGP to eBGP Leaking ------------
# Create update for a route leaking from iBGP to eBGP
leak_update = BGPHeader(type=2)/BGPUpdate()

# Create attributes indicating the leak
# Different next hop
leak_next_hop_attr = BGPPathAttr(type_flags=0x40, type_code=3)
leak_next_hop_attr.attribute = BGPPANextHop(next_hop="10.1.1.1")  # Internal next-hop

# LOCAL_PREF (only present in iBGP, but leaking to eBGP)
# Create custom community indicating route leaking
leak_communities_list = []
leak_communities_list.append(BGPPACommunity(community=0xFFFF0003))  # Custom "LEAKED" community

leak_communities_attr = BGPPathAttr(type_flags=0x40|0x80, type_code=8)
leak_communities_attr.attribute = leak_communities_list

# Create update message for leaked route
leak_update.path_attr = [
    origin,
    as_path_attr,         # Normal AS path
    leak_next_hop_attr,   # Internal next-hop
    med_attr,
    local_pref_attr,      # LOCAL_PREF leaking to eBGP (unusual)
    leak_communities_attr,
]

# Add internal prefixes that should not have been leaked
leak_update.nlri.append(BGPNLRI_IPv4(prefix="172.16.0.0/24"))  # RFC1918 private address

# Send leaked route message
leak_pkt = Ether(src=src_mac, dst=dst_mac)/IP(src=src_ipv4, dst=dst_ipv4, ttl=1, flags="DF", tos=0xC0, id=src_ip_id+23)/TCP(sport=sport, dport=dport, flags="PA", seq=seq_a_v4, ack=seq_b_v4, window=16384)/leak_update
if len(leak_pkt) < 60:
    pad_len = 60 - len(leak_pkt)
    leak_pkt = leak_pkt/Padding(load=b'\x00' * pad_len)
pkts.append(leak_pkt)
seq_a_v4 += len(leak_update)

# ACK for leaked route message
leak_ack = Ether(src=dst_mac, dst=src_mac)/IP(src=dst_ipv4, dst=src_ipv4, ttl=1, flags=0, tos=0xC0, id=dst_ip_id+21)/TCP(sport=dport, dport=sport, flags="A", seq=seq_b_v4, ack=seq_a_v4, window=16384)
if len(leak_ack) < 60:
    pad_len = 60 - len(leak_ack)
    leak_ack = leak_ack/Padding(load=b'\x00' * pad_len)
pkts.append(leak_ack)

# ------------ Scenario 14: IPv4/IPv6 Withdrawals Using MP_UNREACH_NLRI ------------
# Create MP_UNREACH_NLRI for IPv6 withdrawals over IPv4 transport
mp_unreach_withdraw_v4 = BGPHeader(type=2)/BGPUpdate()

# Create MP_UNREACH_NLRI attribute
mp_unreach_attr_v4 = BGPPathAttr(type_flags=0x80, type_code=15)  # MP_UNREACH_NLRI type code is 15

# In some versions of Scapy, the BGPPAMPUnreachNLRI class might have different field names
# Let's inspect what's available in the current Scapy version
print("[*] Creating MP_UNREACH_NLRI attribute for IPv6...")

try:
    # Try creating a basic MP_UNREACH_NLRI without the withdrawn field first
    mp_unreach_v4 = BGPPAMPUnreachNLRI(
        afi=2,                # IPv6 = 2
        safi=1                # Unicast = 1
    )
    
    # If we have NLRI field instead of withdrawn
    if hasattr(mp_unreach_v4, 'nlri'):
        withdrawn_ipv6_prefixes = ["2001:db8:2::/48"]  # Withdraw one of the original IPv6 prefixes
        withdrawn_ipv6_objs = []
        for prefix in withdrawn_ipv6_prefixes:
            withdrawn_ipv6_objs.append(BGPNLRI_IPv6(prefix=prefix))
        mp_unreach_v4.nlri = withdrawn_ipv6_objs
        print("[*] Using 'nlri' field for MP_UNREACH_NLRI")
    elif hasattr(mp_unreach_v4, 'withdraw'):
        withdrawn_ipv6_prefixes = ["2001:db8:2::/48"] 
        withdrawn_ipv6_objs = []
        for prefix in withdrawn_ipv6_prefixes:
            withdrawn_ipv6_objs.append(BGPNLRI_IPv6(prefix=prefix))
        mp_unreach_v4.withdraw = withdrawn_ipv6_objs
        print("[*] Using 'withdraw' field for MP_UNREACH_NLRI")
    
except Exception as e:
    print(f"[!] Error creating MP_UNREACH_NLRI: {e}")
    print("[*] Falling back to a simple withdrawal message")
    # Create a simple UPDATE message with empty path attributes
    mp_unreach_withdraw_v4 = BGPHeader(type=2)/BGPUpdate()
    mp_unreach_withdraw_v4.path_attr = []
    mp_unreach_attr_v4 = None  # Skip creating the MP_UNREACH_NLRI attribute

if mp_unreach_attr_v4 is not None:
    mp_unreach_attr_v4.attribute = mp_unreach_v4
    # Add the MP_UNREACH_NLRI attribute to the update
    mp_unreach_withdraw_v4.path_attr = [mp_unreach_attr_v4]

# Send MP_UNREACH_NLRI update over IPv4
mp_unreach_pkt_v4 = Ether(src=src_mac, dst=dst_mac)/IP(src=src_ipv4, dst=dst_ipv4, ttl=1, flags="DF", tos=0xC0, id=src_ip_id+24)/TCP(sport=sport, dport=dport, flags="PA", seq=seq_a_v4, ack=seq_b_v4, window=16384)/mp_unreach_withdraw_v4
if len(mp_unreach_pkt_v4) < 60:
    pad_len = 60 - len(mp_unreach_pkt_v4)
    mp_unreach_pkt_v4 = mp_unreach_pkt_v4/Padding(load=b'\x00' * pad_len)
pkts.append(mp_unreach_pkt_v4)
seq_a_v4 += len(mp_unreach_withdraw_v4)

# ACK for MP_UNREACH_NLRI
mp_unreach_ack_v4 = Ether(src=dst_mac, dst=src_mac)/IP(src=dst_ipv4, dst=src_ipv4, ttl=1, flags=0, tos=0xC0, id=dst_ip_id+22)/TCP(sport=dport, dport=sport, flags="A", seq=seq_b_v4, ack=seq_a_v4, window=16384)
if len(mp_unreach_ack_v4) < 60:
    pad_len = 60 - len(mp_unreach_ack_v4)
    mp_unreach_ack_v4 = mp_unreach_ack_v4/Padding(load=b'\x00' * pad_len)
pkts.append(mp_unreach_ack_v4)

# Create directories if they don't exist
os.makedirs("pcaps", exist_ok=True)

# Write to pcap
wrpcap("pcaps/realistic_bgp_complete_scenarios.pcap", pkts)
print("✅ Wrote pcaps/realistic_bgp_complete_scenarios.pcap with comprehensive BGP scenarios")