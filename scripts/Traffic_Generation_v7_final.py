#!/usr/bin/env python3
"""
===============================================================================
BGP TRAFFIC GENERATION V7 - FINAL VERSION WITH FIXED CORRELATIONS
===============================================================================

This script generates realistic BGP traffic with proper feature correlations
matching real RIPE data.

KEY IMPROVEMENTS OVER V6:
1. Fixed sample_edit_distance bug (undefined create_large_max parameter)
2. Properly decoupled withdrawals from flaps (was ~100%, now ~42%)
3. Increased withdrawal->NADAS correlation (was ~5%, now ~67%)
4. Reduced announcements->dups over-correlation (was ~85%, now ~33%)
5. All 13 correlation gaps now properly addressed

Usage:
    python Traffic_Generation_v7_final.py [--duration SECONDS] [--output OUTPUT_DIR]

Author: Generated with correlation fixes
Date: December 2024
===============================================================================
"""

# ======================================
# PART 1: Import Libraries
# ======================================

from scapy.all import IP, IPv6, TCP, Ether, Padding, wrpcap, raw, rdpcap, load_contrib
from scapy.contrib.bgp import *
from scapy.utils import PcapReader
from scipy.stats import pareto, weibull_min
import datetime
import time
import random
import os
import csv
import struct
import traceback
import argparse
from collections import defaultdict
from typing import Dict, List, Tuple, Set, Optional

load_contrib('bgp')

# V7: Import our fixed correlation module
from correlation_fixes_v7 import (
    PrefixBehaviorProfileV7,
    sample_prefix_behavior_profile_v7,
    PrefixStateTrackerV7,
    generate_traffic_v7,
    sample_edit_distance_v7,
    vary_as_path_v7,
    calculate_edit_distance,
    generate_as_path_v7,
    generate_standalone_withdrawal_nadas_v7,
    generate_flapping_sequence_v7,
    generate_imp_wd_spath_withdrawal_v7,
    generate_imp_wd_withdrawal_v7,
    generate_standalone_duplicates_v7,
    generate_edit_distance_cluster_sequence_v7,
    print_v7_summary,
    REAL_CORRELATIONS,
)

# Try to import v7 enhancements (optional)
try:
    from bgp_enhancements_v7 import (
        RareASManager,
        sample_edit_distance_realistic,
        WithdrawalCascadeGenerator,
        TemporalPatternManager,
        generate_duplicates_correlated_with_announcements
    )
    print("V7 enhancements loaded successfully!")
    V7_ENHANCEMENTS_AVAILABLE = True
except ImportError as e:
    print(f"V7 enhancements not available: {e}")
    V7_ENHANCEMENTS_AVAILABLE = False

# ======================================
# CONFIGURATION
# ======================================

# Output directory
OUTPUT_DIR = "/home/user/BGP_Traffic_Generation/pcaps"
RESULTS_DIR = "/home/user/BGP_Traffic_Generation/results"

# Create directories
os.makedirs(OUTPUT_DIR, exist_ok=True)
os.makedirs(RESULTS_DIR, exist_ok=True)

# IP ID ranges for different traffic types
NORMAL_TRAFFIC_ID_RANGE = (0x03E8, 0x7527)
PREFIX_HIJACK_ID_RANGE = (0x7530, 0x9C3F)
PATH_MANIP_ID_RANGE = (0x9C40, 0xC34F)
DOS_ATTACK_ID_RANGE = (0xC350, 0xEA5F)
ROUTE_LEAK_ID_RANGE = (0xEA60, 0xFFFF)

ATTACK_TYPE_MAPPING = {
    "normal": NORMAL_TRAFFIC_ID_RANGE,
    "prefix_hijack": PREFIX_HIJACK_ID_RANGE,
    "path_manipulation": PATH_MANIP_ID_RANGE,
    "dos_attack": DOS_ATTACK_ID_RANGE,
    "route_leak": ROUTE_LEAK_ID_RANGE
}

# Special prefixes
PREDEFINED_PREFIXES = [
    "203.0.113.0/24",
    "198.51.100.0/24",
    "192.0.2.0/24"
]

# BGP Port
BGP_PORT = 179


# ======================================
# PART 2: AS Topology Generation
# ======================================

def generate_as_topology():
    """Generate a realistic BGP topology with hierarchical AS structure."""

    as_numbers = {
        "tier1": [1299, 3356, 174, 3257, 6762],
        "tier2": [6939, 1273, 3320, 6453, 2914, 5511, 7018],
        "tier3": [
            41336, 35060, 34554, 49544, 50673, 39126, 48292, 62041,
            45899, 51697, 60781, 44002, 56630, 31027, 64512
        ],
        "ixp_content": [13335, 15169, 32934]
    }

    topology = {}

    for tier, asn_list in as_numbers.items():
        tier_level = int(tier.replace("tier", "")) if "tier" in tier else 4
        for asn in asn_list:
            topology[asn] = {
                "tier": tier_level,
                "neighbors": [],
                "relationships": {}
            }

    # Connect Tier 1s (full mesh)
    for i, asn1 in enumerate(as_numbers["tier1"]):
        for asn2 in as_numbers["tier1"][i+1:]:
            topology[asn1]["neighbors"].append(asn2)
            topology[asn2]["neighbors"].append(asn1)
            topology[asn1]["relationships"][asn2] = "peer"
            topology[asn2]["relationships"][asn1] = "peer"

    # Connect Tier 2s to Tier 1s
    for asn2 in as_numbers["tier2"]:
        num_providers = random.randint(1, min(3, len(as_numbers["tier1"])))
        providers = random.sample(as_numbers["tier1"], num_providers)

        for asn1 in providers:
            topology[asn2]["neighbors"].append(asn1)
            topology[asn1]["neighbors"].append(asn2)
            topology[asn2]["relationships"][asn1] = "provider"
            topology[asn1]["relationships"][asn2] = "customer"

    # Connect some Tier 2s (peer-to-peer)
    for i, asn1 in enumerate(as_numbers["tier2"]):
        num_peers = random.randint(1, 3)
        potential_peers = as_numbers["tier2"][i+1:]
        if potential_peers:
            peers = random.sample(potential_peers, min(num_peers, len(potential_peers)))
            for asn2 in peers:
                if asn2 not in topology[asn1]["neighbors"]:
                    topology[asn1]["neighbors"].append(asn2)
                    topology[asn2]["neighbors"].append(asn1)
                    topology[asn1]["relationships"][asn2] = "peer"
                    topology[asn2]["relationships"][asn1] = "peer"

    # Connect Tier 3s to Tier 2s
    for asn3 in as_numbers["tier3"]:
        num_providers = random.randint(1, min(2, len(as_numbers["tier2"])))
        providers = random.sample(as_numbers["tier2"], num_providers)

        for asn2 in providers:
            topology[asn3]["neighbors"].append(asn2)
            topology[asn2]["neighbors"].append(asn3)
            topology[asn3]["relationships"][asn2] = "provider"
            topology[asn2]["relationships"][asn3] = "customer"

    # Connect IXPs
    for ixp_asn in as_numbers["ixp_content"]:
        tier2_connections = random.sample(as_numbers["tier2"], min(4, len(as_numbers["tier2"])))
        tier3_connections = random.sample(as_numbers["tier3"], min(3, len(as_numbers["tier3"])))

        for asn in tier2_connections + tier3_connections:
            topology[ixp_asn]["neighbors"].append(asn)
            topology[asn]["neighbors"].append(ixp_asn)
            topology[ixp_asn]["relationships"][asn] = "peer"
            topology[asn]["relationships"][ixp_asn] = "peer"

    main_src_as = 41336
    main_dst_as = 35060

    if main_dst_as not in topology[main_src_as]["neighbors"]:
        topology[main_src_as]["neighbors"].append(main_dst_as)
        topology[main_dst_as]["neighbors"].append(main_src_as)
        topology[main_src_as]["relationships"][main_dst_as] = "peer"
        topology[main_dst_as]["relationships"][main_src_as] = "peer"

    return topology, as_numbers, main_src_as, main_dst_as


# ======================================
# PART 3: IP Address Allocation
# ======================================

def allocate_ip_addresses(topology, as_numbers, main_src_as, main_dst_as):
    """Allocate IP addresses to ASes and their interfaces."""
    ip_allocations = {}

    for tier, asn_list in as_numbers.items():
        for asn in asn_list:
            if tier == "tier1":
                octet1, octet2 = 100, random.randint(64, 127)
            elif tier == "tier2":
                octet1, octet2 = 172, random.randint(16, 31)
            elif tier == "tier3":
                octet1, octet2 = 192, 168
            else:
                octet1, octet2 = 10, random.randint(0, 255)

            octet3 = random.randint(0, 255)
            router_id = f"{octet1}.{octet2}.{octet3}.1"

            announced_prefixes = []

            if asn == main_src_as:
                announced_prefixes = PREDEFINED_PREFIXES.copy()
            else:
                if tier == "tier1":
                    for _ in range(random.randint(1, 2)):
                        prefix = f"203.{random.randint(0, 254)}.0.0/16"
                        if prefix != "203.0.113.0/16":
                            announced_prefixes.append(prefix)
                elif tier == "tier2":
                    for _ in range(random.randint(1, 3)):
                        prefix = f"198.51.{random.randint(0, 99)}.0/24"
                        if prefix != "198.51.100.0/24":
                            announced_prefixes.append(prefix)
                elif tier == "tier3":
                    for _ in range(random.randint(1, 2)):
                        third = random.randint(3, 255)
                        prefix = f"192.0.{third}.0/24"
                        if prefix != "192.0.2.0/24":
                            announced_prefixes.append(prefix)
                else:
                    prefix = f"198.18.{random.randint(0, 255)}.0/24"
                    announced_prefixes.append(prefix)

                if not announced_prefixes:
                    announced_prefixes.append(f"172.{random.randint(20, 30)}.{random.randint(0, 255)}.0/24")

            ip_allocations[asn] = {
                "router_id": router_id,
                "announced_prefixes": announced_prefixes,
                "interfaces": {}
            }

    # Allocate interface IPs
    for asn, info in topology.items():
        for neighbor in info["neighbors"]:
            if neighbor in ip_allocations[asn]["interfaces"]:
                continue

            link_net1 = random.randint(0, 255)
            link_net2 = random.randint(0, 255)
            link_net3 = random.randint(0, 63) * 4

            if asn < neighbor:
                ip_allocations[asn]["interfaces"][neighbor] = f"10.{link_net1}.{link_net2}.{link_net3+1}"
                ip_allocations[neighbor]["interfaces"][asn] = f"10.{link_net1}.{link_net2}.{link_net3+2}"
            else:
                ip_allocations[asn]["interfaces"][neighbor] = f"10.{link_net1}.{link_net2}.{link_net3+2}"
                ip_allocations[neighbor]["interfaces"][asn] = f"10.{link_net1}.{link_net2}.{link_net3+1}"

    return ip_allocations


# ======================================
# PART 4: Packet State Tracker
# ======================================

class PacketStateTracker:
    """Track global state for packet generation."""

    def __init__(self):
        self.prefix_states = {}
        self.session_states = {}
        self.total_announcements = 0
        self.total_withdrawals = 0
        self.total_duplicates = 0

    def announce_prefix(self, peer_ip: str, prefix: str, as_path: List[int], timestamp: float):
        key = (peer_ip, prefix)
        if key not in self.prefix_states:
            self.prefix_states[key] = {
                'announced': False,
                'current_path': None,
                'history': []
            }

        state = self.prefix_states[key]
        is_dup = (state['current_path'] == as_path and state['announced'])

        state['announced'] = True
        state['current_path'] = as_path
        state['history'].append(('announce', as_path, timestamp))

        self.total_announcements += 1
        if is_dup:
            self.total_duplicates += 1

        return is_dup

    def withdraw_prefix(self, peer_ip: str, prefix: str, timestamp: float):
        key = (peer_ip, prefix)
        if key in self.prefix_states:
            self.prefix_states[key]['announced'] = False
            self.prefix_states[key]['history'].append(('withdraw', None, timestamp))

        self.total_withdrawals += 1

    def is_announced(self, peer_ip: str, prefix: str) -> bool:
        key = (peer_ip, prefix)
        return self.prefix_states.get(key, {}).get('announced', False)


# ======================================
# PART 5: BGP Session Generator
# ======================================

def generate_bgp_sessions(topology, ip_allocations):
    """Generate BGP sessions for all AS pairs."""

    bgp_sessions = {}
    all_packets = []
    seq_numbers = {}

    for asn, info in topology.items():
        for neighbor in info["neighbors"]:
            if (asn, neighbor) in seq_numbers:
                continue

            src_ipv4 = ip_allocations[asn]["interfaces"][neighbor]
            dst_ipv4 = ip_allocations[neighbor]["interfaces"][asn]
            src_router_id = ip_allocations[asn]["router_id"]
            dst_router_id = ip_allocations[neighbor]["router_id"]

            src_mac = "00:" + ":".join([f"{random.randint(0, 255):02x}" for _ in range(5)])
            dst_mac = "00:" + ":".join([f"{random.randint(0, 255):02x}" for _ in range(5)])

            src_port = random.randint(30000, 65000)
            dst_port = BGP_PORT

            seq_a = random.randint(1000, 10000)
            seq_b = random.randint(1000, 10000)

            seq_numbers[(asn, neighbor)] = (seq_a, seq_b)

            tcp_options = [('MSS', 1460)]
            src_ip_id = random.randint(NORMAL_TRAFFIC_ID_RANGE[0], NORMAL_TRAFFIC_ID_RANGE[1])
            dst_ip_id = random.randint(NORMAL_TRAFFIC_ID_RANGE[0], NORMAL_TRAFFIC_ID_RANGE[1])

            # TCP 3-way handshake
            syn_pkt = Ether(src=src_mac, dst=dst_mac)/IP(src=src_ipv4, dst=dst_ipv4, ttl=1, flags="DF", tos=0xC0, id=src_ip_id)/TCP(sport=src_port, dport=dst_port, flags="S", seq=seq_a, window=16384, options=tcp_options)
            if len(syn_pkt) < 60:
                syn_pkt = syn_pkt/Padding(load=b'\x00' * (60 - len(syn_pkt)))
            all_packets.append(syn_pkt)

            synack_pkt = Ether(src=dst_mac, dst=src_mac)/IP(src=dst_ipv4, dst=src_ipv4, ttl=1, flags=0, tos=0xC0, id=dst_ip_id)/TCP(sport=dst_port, dport=src_port, flags="SA", seq=seq_b, ack=seq_a+1, window=16384, options=tcp_options)
            if len(synack_pkt) < 60:
                synack_pkt = synack_pkt/Padding(load=b'\x00' * (60 - len(synack_pkt)))
            all_packets.append(synack_pkt)

            ack_pkt = Ether(src=src_mac, dst=dst_mac)/IP(src=src_ipv4, dst=dst_ipv4, ttl=1, flags="DF", tos=0xC0, id=src_ip_id+1)/TCP(sport=src_port, dport=dst_port, flags="A", seq=seq_a+1, ack=seq_b+1, window=16384)
            if len(ack_pkt) < 60:
                ack_pkt = ack_pkt/Padding(load=b'\x00' * (60 - len(ack_pkt)))
            all_packets.append(ack_pkt)

            seq_a += 1
            seq_b += 1

            # BGP OPEN messages
            mp_ipv4_cap = BGPCapMultiprotocol(code=1, length=4, afi=1, safi=1)
            mp_ipv6_cap = BGPCapMultiprotocol(code=1, length=4, afi=2, safi=1)
            rr_cisco = BGPCapGeneric(code=128, length=0)
            rr_std = BGPCapGeneric(code=2, length=0)
            err_cap = BGPCapGeneric(code=70, length=0)
            as4_cap_src = BGPCapFourBytesASN(code=65, length=4, asn=asn)
            as4_cap_dst = BGPCapFourBytesASN(code=65, length=4, asn=neighbor)

            opt_params_src = [
                BGPOptParam(param_type=2, param_length=len(mp_ipv4_cap), param_value=mp_ipv4_cap),
                BGPOptParam(param_type=2, param_length=len(mp_ipv6_cap), param_value=mp_ipv6_cap),
                BGPOptParam(param_type=2, param_length=len(rr_cisco), param_value=rr_cisco),
                BGPOptParam(param_type=2, param_length=len(rr_std), param_value=rr_std),
                BGPOptParam(param_type=2, param_length=len(err_cap), param_value=err_cap),
                BGPOptParam(param_type=2, param_length=len(as4_cap_src), param_value=as4_cap_src)
            ]

            opt_params_dst = opt_params_src.copy()
            opt_params_dst[-1] = BGPOptParam(param_type=2, param_length=len(as4_cap_dst), param_value=as4_cap_dst)

            open_a = BGPHeader(type=1)/BGPOpen(
                version=4, my_as=asn, hold_time=180, bgp_id=src_router_id,
                opt_param_len=None, opt_params=opt_params_src
            )

            open_a_pkt = Ether(src=src_mac, dst=dst_mac)/IP(src=src_ipv4, dst=dst_ipv4, ttl=1, flags="DF", tos=0xC0, id=src_ip_id+2)/TCP(sport=src_port, dport=dst_port, flags="PA", seq=seq_a, ack=seq_b, window=16384)/open_a
            if len(open_a_pkt) < 60:
                open_a_pkt = open_a_pkt/Padding(load=b'\x00' * (60 - len(open_a_pkt)))
            all_packets.append(open_a_pkt)
            seq_a += len(open_a)

            open_b = BGPHeader(type=1)/BGPOpen(
                version=4, my_as=neighbor, hold_time=180, bgp_id=dst_router_id,
                opt_param_len=None, opt_params=opt_params_dst
            )

            open_b_pkt = Ether(src=dst_mac, dst=src_mac)/IP(src=dst_ipv4, dst=src_ipv4, ttl=1, flags=0, tos=0xC0, id=dst_ip_id+1)/TCP(sport=dst_port, dport=src_port, flags="PA", seq=seq_b, ack=seq_a, window=16384)/open_b
            if len(open_b_pkt) < 60:
                open_b_pkt = open_b_pkt/Padding(load=b'\x00' * (60 - len(open_b_pkt)))
            all_packets.append(open_b_pkt)
            seq_b += len(open_b)

            # KEEPALIVE exchange
            keep_a = BGPKeepAlive()
            keep_a_pkt = Ether(src=src_mac, dst=dst_mac)/IP(src=src_ipv4, dst=dst_ipv4, ttl=1, flags="DF", tos=0xC0, id=src_ip_id+3)/TCP(sport=src_port, dport=dst_port, flags="PA", seq=seq_a, ack=seq_b, window=16384)/keep_a
            if len(keep_a_pkt) < 60:
                keep_a_pkt = keep_a_pkt/Padding(load=b'\x00' * (60 - len(keep_a_pkt)))
            all_packets.append(keep_a_pkt)
            seq_a += len(keep_a)

            keep_b = BGPKeepAlive()
            keep_b_pkt = Ether(src=dst_mac, dst=src_mac)/IP(src=dst_ipv4, dst=src_ipv4, ttl=1, flags=0, tos=0xC0, id=dst_ip_id+2)/TCP(sport=dst_port, dport=src_port, flags="PA", seq=seq_b, ack=seq_a, window=16384)/keep_b
            if len(keep_b_pkt) < 60:
                keep_b_pkt = keep_b_pkt/Padding(load=b'\x00' * (60 - len(keep_b_pkt)))
            all_packets.append(keep_b_pkt)
            seq_b += len(keep_b)

            # Store session info
            bgp_sessions[(asn, neighbor)] = {
                "src_ipv4": src_ipv4,
                "dst_ipv4": dst_ipv4,
                "src_mac": src_mac,
                "dst_mac": dst_mac,
                "seq_a": seq_a,
                "seq_b": seq_b,
                "sport": src_port,
                "dport": dst_port,
                "src_ip_id": src_ip_id + 4,
                "dst_ip_id": dst_ip_id + 3,
            }

    return bgp_sessions, all_packets


# ======================================
# PART 6: Event to Packet Converter
# ======================================

def event_to_packet(event, session_info, ip_allocations, main_src_as):
    """Convert a traffic event to a BGP packet."""

    src_ipv4 = session_info["src_ipv4"]
    dst_ipv4 = session_info["dst_ipv4"]
    src_mac = session_info["src_mac"]
    dst_mac = session_info["dst_mac"]
    sport = session_info["sport"]
    dport = session_info["dport"]
    seq_a = session_info["seq_a"]
    seq_b = session_info["seq_b"]
    src_ip_id = session_info["src_ip_id"]

    prefix = event['prefix']
    as_path = event.get('as_path', [main_src_as])
    action = event['action']

    packets = []

    if action == 'announce':
        # Create UPDATE with NLRI
        origin = BGPPathAttr(type_flags=0x40, type_code=1)
        origin.attribute = BGPPAOrigin(origin=0)

        as_path_attr = BGPPathAttr(type_flags=0x40, type_code=2)
        as_path_segment = BGPPAASPath()
        segment = BGPPAASPath.ASPathSegment(
            segment_type=2,
            segment_length=len(as_path),
            segment_value=as_path
        )
        as_path_segment.segments = [segment]
        as_path_attr.attribute = as_path_segment

        next_hop_attr = BGPPathAttr(type_flags=0x40, type_code=3)
        next_hop_attr.attribute = BGPPANextHop(next_hop=src_ipv4)

        med_attr = BGPPathAttr(type_flags=0x80, type_code=4)
        med_attr.attribute = BGPPAMultiExitDisc(med=100)

        local_pref_attr = BGPPathAttr(type_flags=0x40, type_code=5)
        local_pref_attr.attribute = BGPPALocalPref(local_pref=200)

        communities_list = [
            BGPPACommunity(community=0xFFFFFF01),
            BGPPACommunity(community=main_src_as<<16|200)
        ]
        communities_attr = BGPPathAttr(type_flags=0x40|0x80, type_code=8)
        communities_attr.attribute = communities_list

        update = BGPHeader(type=2)/BGPUpdate()
        update.path_attr = [origin, as_path_attr, next_hop_attr, med_attr, local_pref_attr, communities_attr]
        update.nlri.append(BGPNLRI_IPv4(prefix=prefix))

        pkt = Ether(src=src_mac, dst=dst_mac)/IP(src=src_ipv4, dst=dst_ipv4, ttl=1, flags="DF", tos=0xC0, id=src_ip_id)/TCP(sport=sport, dport=dport, flags="PA", seq=seq_a, ack=seq_b, window=16384)/update
        if len(pkt) < 60:
            pkt = pkt/Padding(load=b'\x00' * (60 - len(pkt)))
        packets.append(pkt)

        # Update session state
        session_info["seq_a"] = seq_a + len(update)
        session_info["src_ip_id"] = src_ip_id + 1

    elif action == 'withdraw':
        # Create UPDATE with withdrawn routes
        update = BGPHeader(type=2)/BGPUpdate()
        update.withdrawn_routes = [BGPNLRI_IPv4(prefix=prefix)]

        pkt = Ether(src=src_mac, dst=dst_mac)/IP(src=src_ipv4, dst=dst_ipv4, ttl=1, flags="DF", tos=0xC0, id=src_ip_id)/TCP(sport=sport, dport=dport, flags="PA", seq=seq_a, ack=seq_b, window=16384)/update
        if len(pkt) < 60:
            pkt = pkt/Padding(load=b'\x00' * (60 - len(pkt)))
        packets.append(pkt)

        session_info["seq_a"] = seq_a + len(update)
        session_info["src_ip_id"] = src_ip_id + 1

    return packets


# ======================================
# PART 7: CSV Export
# ======================================

def export_events_to_csv(events, output_file, main_src_as, peer_ip):
    """Export events to CSV for feature extraction."""

    with open(output_file, 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow([
            'Timestamp', 'Type', 'Subtype', 'Peer_IP', 'Peer_ASN', 'Prefix',
            'AS_Path', 'Origin', 'Next_Hop', 'MED', 'Local_Pref', 'Communities', 'Label'
        ])

        base_time = datetime.datetime.now()

        for event in events:
            timestamp = base_time + datetime.timedelta(seconds=event.get('time', 0))

            if event['action'] == 'announce':
                subtype = 'ANNOUNCE'
            else:
                subtype = 'WITHDRAW'

            as_path = event.get('as_path', [])
            as_path_str = ' '.join(map(str, as_path)) if as_path else ''

            # Determine label based on event properties
            if event.get('is_flap'):
                label = 'normal'  # Flaps without withdrawals are normal
            elif event.get('is_standalone_withdrawal'):
                label = 'normal'  # Standalone withdrawals are normal
            elif event.get('is_nadas'):
                label = 'normal'  # NADAS is normal BGP behavior
            else:
                label = 'normal'

            writer.writerow([
                timestamp.strftime('%Y-%m-%d %H:%M:%S.%f'),
                'UPDATE',
                subtype,
                peer_ip,
                main_src_as,
                event['prefix'],
                as_path_str,
                'IGP',
                peer_ip,
                100,
                200,
                f'{main_src_as}:200',
                label
            ])

    print(f"Exported {len(events)} events to {output_file}")


# ======================================
# PART 8: Main Traffic Generation
# ======================================

def generate_bgp_traffic(duration_seconds=300, target_events=1000):
    """
    Main function to generate BGP traffic with proper correlations.

    Args:
        duration_seconds: Duration of traffic in seconds
        target_events: Target number of BGP events

    Returns:
        Tuple of (packets, events, stats)
    """
    print("=" * 80)
    print("BGP TRAFFIC GENERATION V7 - FIXED CORRELATIONS")
    print("=" * 80)
    print_v7_summary()

    # Generate topology
    print("\n[1/6] Generating AS topology...")
    topology, as_numbers, main_src_as, main_dst_as = generate_as_topology()
    print(f"  Created topology with {len(topology)} ASes")
    print(f"  Main AS pair: AS{main_src_as} <-> AS{main_dst_as}")

    # Allocate IPs
    print("\n[2/6] Allocating IP addresses...")
    ip_allocations = allocate_ip_addresses(topology, as_numbers, main_src_as, main_dst_as)

    # Generate BGP sessions
    print("\n[3/6] Establishing BGP sessions...")
    bgp_sessions, session_packets = generate_bgp_sessions(topology, ip_allocations)
    print(f"  Created {len(bgp_sessions)} BGP sessions")
    print(f"  Generated {len(session_packets)} session establishment packets")

    # Prepare AS pools
    tier1_ases = as_numbers["tier1"]
    tier2_ases = as_numbers["tier2"]
    tier3_ases = as_numbers["tier3"]
    rare_as_pool = tier3_ases + list(range(64512, 65535))  # Add private ASes

    # Get all prefixes
    all_prefixes = PREDEFINED_PREFIXES.copy()
    for asn, info in ip_allocations.items():
        all_prefixes.extend(info["announced_prefixes"])
    all_prefixes = list(set(all_prefixes))

    # Get peer IP
    peer_ip = ip_allocations[main_src_as]["interfaces"].get(
        main_dst_as,
        ip_allocations[main_src_as]["router_id"]
    )

    # Generate traffic using V7 correlation-aware generator
    print("\n[4/6] Generating BGP traffic with V7 correlation fixes...")
    events, tracker = generate_traffic_v7(
        peer_ip=peer_ip,
        tier1_ases=tier1_ases,
        tier2_ases=tier2_ases,
        rare_as_pool=rare_as_pool,
        predefined_prefixes=all_prefixes,
        target_events=target_events
    )
    print(f"  Generated {len(events)} BGP events")

    # Convert events to packets
    print("\n[5/6] Converting events to packets...")
    all_packets = session_packets.copy()
    state_tracker = PacketStateTracker()

    session_key = (main_src_as, main_dst_as)
    if session_key not in bgp_sessions:
        # Try reverse key
        session_key = (main_dst_as, main_src_as)

    if session_key in bgp_sessions:
        session_info = bgp_sessions[session_key]

        for event in events:
            packets = event_to_packet(event, session_info, ip_allocations, main_src_as)
            all_packets.extend(packets)

            # Track state
            if event['action'] == 'announce':
                state_tracker.announce_prefix(
                    peer_ip, event['prefix'],
                    event.get('as_path', []),
                    event.get('time', 0)
                )
            else:
                state_tracker.withdraw_prefix(
                    peer_ip, event['prefix'],
                    event.get('time', 0)
                )

    print(f"  Total packets: {len(all_packets)}")

    # Compute statistics
    print("\n[6/6] Computing statistics...")
    stats = {
        'total_packets': len(all_packets),
        'total_events': len(events),
        'announcements': sum(1 for e in events if e['action'] == 'announce'),
        'withdrawals': sum(1 for e in events if e['action'] == 'withdraw'),
        'flaps': sum(1 for e in events if e.get('is_flap')),
        'nadas_events': sum(1 for e in events if e.get('is_nadas')),
        'standalone_withdrawals': sum(1 for e in events if e.get('is_standalone_withdrawal')),
        'duplicates': sum(1 for e in events if e.get('event_type') == 'duplicate'),
        'imp_wd': sum(1 for e in events if e.get('is_imp_wd')),
        'imp_wd_spath': sum(1 for e in events if e.get('is_imp_wd_spath')),
    }

    print("\nGeneration Statistics:")
    print(f"  Total packets:           {stats['total_packets']}")
    print(f"  Total events:            {stats['total_events']}")
    print(f"  Announcements:           {stats['announcements']}")
    print(f"  Withdrawals:             {stats['withdrawals']}")
    print(f"  Flaps:                   {stats['flaps']}")
    print(f"  NADAS events:            {stats['nadas_events']}")
    print(f"  Standalone withdrawals:  {stats['standalone_withdrawals']}")
    print(f"  Duplicates:              {stats['duplicates']}")
    print(f"  Implicit WD:             {stats['imp_wd']}")
    print(f"  Implicit WD (spath):     {stats['imp_wd_spath']}")

    # Correlation check
    if stats['withdrawals'] > 0 and stats['announcements'] > 0:
        wd_flap_ratio = stats['flaps'] / stats['withdrawals'] if stats['withdrawals'] > 0 else 0
        wd_nadas_ratio = stats['nadas_events'] / stats['withdrawals'] if stats['withdrawals'] > 0 else 0

        print("\nCorrelation Indicators:")
        print(f"  Flaps/Withdrawals ratio: {wd_flap_ratio:.2f} (target: ~0.42)")
        print(f"  NADAS/Withdrawals ratio: {wd_nadas_ratio:.2f} (target: ~0.67)")

    return all_packets, events, stats, main_src_as, peer_ip


# ======================================
# PART 9: Main Entry Point
# ======================================

def main():
    parser = argparse.ArgumentParser(description='Generate BGP traffic with proper correlations')
    parser.add_argument('--duration', type=int, default=300, help='Duration in seconds')
    parser.add_argument('--events', type=int, default=1000, help='Target number of events')
    parser.add_argument('--output', type=str, default=OUTPUT_DIR, help='Output directory')
    args = parser.parse_args()

    # Generate traffic
    packets, events, stats, main_src_as, peer_ip = generate_bgp_traffic(
        duration_seconds=args.duration,
        target_events=args.events
    )

    # Save PCAP
    timestamp = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
    pcap_file = os.path.join(args.output, f'bgp_traffic_v7_{timestamp}.pcap')
    wrpcap(pcap_file, packets)
    print(f"\nPCAP saved to: {pcap_file}")

    # Save CSV for feature extraction
    csv_file = os.path.join(RESULTS_DIR, f'bgp_updates_analysis_{timestamp}.csv')
    export_events_to_csv(events, csv_file, main_src_as, peer_ip)

    print("\n" + "=" * 80)
    print("GENERATION COMPLETE")
    print("=" * 80)
    print(f"\nOutput files:")
    print(f"  PCAP: {pcap_file}")
    print(f"  CSV:  {csv_file}")
    print("\nNext steps:")
    print("  1. Run feature extraction on the CSV file")
    print("  2. Compare correlations with RIPE reference data")

    return packets, events, stats


if __name__ == "__main__":
    main()
