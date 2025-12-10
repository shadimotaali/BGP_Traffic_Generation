# improved_bgp_analyzer.py
from scapy.all import rdpcap, IP, IPv6, raw
from scapy.contrib.bgp import *
import binascii
import struct

# Load the packets
pcap_file = "pcaps/realistic_bgp_complete_scenarios.pcap"
packets = rdpcap(pcap_file)

# Analysis results
announcements = 0
withdrawals = 0
mp_reach_count = 0
mp_unreach_count = 0
regular_withdrawals = 0
empty_updates = 0  # Track updates with no announcements or path attributes

print("[*] Analyzing BGP packet capture...")
print(f"[*] Total packets: {len(packets)}")

# First, analyze all BGP messages to get an overview
bgp_types = {1: "OPEN", 2: "UPDATE", 3: "NOTIFICATION", 4: "KEEPALIVE", 5: "ROUTE-REFRESH"}
bgp_counts = {1: 0, 2: 0, 3: 0, 4: 0, 5: 0}
bgp_packet_indices = {1: [], 2: [], 3: [], 4: [], 5: []}

for i, pkt in enumerate(packets, 1):  # Start index from 1 to match tshark
    if BGPHeader in pkt:
        msg_type = pkt[BGPHeader].type
        if msg_type in bgp_counts:
            bgp_counts[msg_type] += 1
            bgp_packet_indices[msg_type].append(i)

print("\n===== BGP Message Types =====")
for msg_type, name in bgp_types.items():
    count = bgp_counts[msg_type]
    packets_str = ", ".join(str(idx) for idx in bgp_packet_indices[msg_type])
    print(f"{name}: {count} (Packets: {packets_str})")

# Now analyze UPDATE messages in detail
print("\n===== BGP UPDATE Analysis =====")

update_count = 0
# Print detailed structure of all UPDATE messages
for i, pkt in enumerate(packets, 1):  # Start index from 1 to match tshark
    if BGPHeader in pkt and pkt[BGPHeader].type == 2:  # BGP UPDATE
        update_count += 1
        print(f"\n----- UPDATE Packet #{i} (Update #{update_count}) -----")
        bgp_update = pkt[BGPHeader].payload
        
        # Transport protocol info
        if IP in pkt:
            print(f"  Transport: IPv4 {pkt[IP].src} -> {pkt[IP].dst}")
        elif IPv6 in pkt:
            print(f"  Transport: IPv6 {pkt[IPv6].src} -> {pkt[IPv6].dst}")
        
        # Check for standard withdrawals
        withdrawal_found = False
        if hasattr(bgp_update, 'withdrawn_routes') and bgp_update.withdrawn_routes:
            withdrawal_found = True
            regular_withdrawals += len(bgp_update.withdrawn_routes)
            print(f"Standard withdrawals: {len(bgp_update.withdrawn_routes)}")
            for j, w in enumerate(bgp_update.withdrawn_routes):
                if hasattr(w, 'prefix'):
                    withdrawals += 1
                    print(f"  Withdrawn prefix: {w.prefix}")
        
        # Check for NLRI (announcements)
        nlri_found = False
        if hasattr(bgp_update, 'nlri') and bgp_update.nlri:
            nlri_found = True
            print(f"NLRI announcements: {len(bgp_update.nlri)}")
            for j, n in enumerate(bgp_update.nlri):
                if hasattr(n, 'prefix'):
                    announcements += 1
                    print(f"  NLRI prefix: {n.prefix}")
        
        # Check path attributes
        path_attr_found = False
        mp_reach_found = False
        mp_unreach_found = False
        
        if hasattr(bgp_update, 'path_attr') and bgp_update.path_attr:
            path_attr_found = True
            print(f"Path attributes: {len(bgp_update.path_attr)}")
            for j, attr in enumerate(bgp_update.path_attr):
                if hasattr(attr, 'type_code'):
                    # Just show the attribute name rather than code
                    attr_names = {
                        1: "ORIGIN", 2: "AS_PATH", 3: "NEXT_HOP", 4: "MED", 
                        5: "LOCAL_PREF", 6: "ATOMIC_AGGREGATE", 7: "AGGREGATOR",
                        8: "COMMUNITIES", 14: "MP_REACH_NLRI", 15: "MP_UNREACH_NLRI",
                        16: "EXTENDED COMMUNITIES", 17: "AS4_PATH"
                    }
                    attr_name = attr_names.get(attr.type_code, f"Type {attr.type_code}")
                    print(f"  Attribute: {attr_name}")
                    
                    # MP_REACH_NLRI (type 14)
                    if attr.type_code == 14:
                        mp_reach_count += 1
                        mp_reach_found = True
                        print(f"  ** Found MP_REACH_NLRI **")
                        
                        # Show key BGP fields, not all Python properties
                        if hasattr(attr.attribute, 'afi'):
                            print(f"    AFI: {attr.attribute.afi}")  # 1=IPv4, 2=IPv6
                        if hasattr(attr.attribute, 'safi'):
                            print(f"    SAFI: {attr.attribute.safi}")  # 1=unicast
                        
                        if hasattr(attr.attribute, 'nlri'):
                            for k, nlri in enumerate(attr.attribute.nlri):
                                if hasattr(nlri, 'prefix'):
                                    print(f"    MP_REACH prefix: {nlri.prefix}")
                                    announcements += 1
                    
                    # MP_UNREACH_NLRI (type 15)
                    elif attr.type_code == 15:
                        mp_unreach_count += 1
                        mp_unreach_found = True
                        print(f"  ** Found MP_UNREACH_NLRI **")
                        withdrawal_found = True
                        
                        if hasattr(attr.attribute, 'afi'):
                            print(f"    AFI: {attr.attribute.afi}")  # 1=IPv4, 2=IPv6
                        if hasattr(attr.attribute, 'safi'):
                            print(f"    SAFI: {attr.attribute.safi}")  # 1=unicast
                        
                        # Try to extract withdrawn prefixes
                        prefixes_found = False
                        
                        # Check various field names
                        for field_name in ['withdrawn', 'nlri', 'withdraw']:
                            if hasattr(attr.attribute, field_name):
                                field_value = getattr(attr.attribute, field_name)
                                if isinstance(field_value, list):
                                    for item in field_value:
                                        if hasattr(item, 'prefix'):
                                            prefixes_found = True
                                            print(f"    MP_UNREACH prefix: {item.prefix}")
                                            withdrawals += 1
                        
        
        # Detect empty UPDATE messages (likely withdrawals)
        if not nlri_found and not path_attr_found and not withdrawal_found:
            empty_updates += 1
            print(f"  ** Empty UPDATE (no withdrawals, no NLRI, no attributes) ** - Packet #{i}")
        elif not nlri_found and not mp_reach_found and withdrawal_found:
            print("  ** Withdrawal-only UPDATE **")

# Print summary
print("\n===== SUMMARY =====")
print(f"Total announcements found: {announcements}")
print(f"Total withdrawals found: {withdrawals}")
print(f"MP_REACH_NLRI attributes: {mp_reach_count}")
print(f"MP_UNREACH_NLRI attributes: {mp_unreach_count}")
print(f"Regular withdrawals: {regular_withdrawals}")
print(f"Empty UPDATE messages: {empty_updates}")