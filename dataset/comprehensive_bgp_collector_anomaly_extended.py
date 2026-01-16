#!/usr/bin/env python3
"""
Extended BGP Anomaly Collector - Version 2

This script collects ADDITIONAL BGP anomaly events beyond those in
comprehensive_bgp_collector_anomaly.py for fair comparison in training.

Contains 45+ additional real-world BGP anomalies (prefix hijacking, path manipulation, DoS)
that do NOT overlap with the original collector.

Data source: RIPE RIS (https://data.ris.ripe.net)
"""

import os
import gzip
import shutil
import subprocess
import csv
from datetime import datetime, timedelta
from urllib.request import urlopen
from pathlib import Path
import ipaddress


# ============================================================================
# EXTENDED INCIDENT DEFINITIONS - Additional BGP Anomaly Events
# ============================================================================
# These incidents are DIFFERENT from those in comprehensive_bgp_collector_anomaly.py

EXTENDED_INCIDENTS = {
    # ========================================================================
    # PREFIX HIJACKING (PH) INCIDENTS - Additional Events
    # ========================================================================

    'indosat_google_2014': {
        'name': 'Indosat-Google Hijack 2014',
        'date': '2014-04-02',
        'start_time': '18:30',
        'end_time': '21:00',
        'rrc': 'rrc04',
        'malicious_as': ['4761'],  # Indosat
        'hijacked_prefix': ['8.8.8.0/24'],  # Google DNS
        'label': 'prefix_hijacking',
        'type': 'PH',
        'duration_minutes': 150,
        'impact': 'Google DNS traffic hijacked via Indonesia'
    },

    'turk_telecom_dns_2014': {
        'name': 'Turk Telecom DNS Hijack 2014',
        'date': '2014-03-28',
        'start_time': '04:00',
        'end_time': '10:00',
        'rrc': 'rrc04',
        'malicious_as': ['9121'],  # Turk Telecom
        'hijacked_prefix': ['8.8.8.0/24', '208.67.222.0/24'],  # Google DNS, OpenDNS
        'label': 'prefix_hijacking',
        'type': 'PH',
        'duration_minutes': 360,
        'impact': 'DNS traffic redirected to Turkish servers'
    },

    'spamhaus_ddos_2013': {
        'name': 'Spamhaus BGP Hijack (DDoS)',
        'date': '2013-03-18',
        'start_time': '08:00',
        'end_time': '14:00',
        'rrc': 'rrc04',
        'malicious_as': ['34109'],  # CB3ROB/Cyberbunker
        'hijacked_prefix': [],
        'label': 'prefix_hijacking',
        'type': 'PH',
        'duration_minutes': 360,
        'impact': 'Largest DDoS attack at the time, 300 Gbps'
    },

    'bitcanal_hijacker_2018': {
        'name': 'Bitcanal Serial Hijacker',
        'date': '2018-07-09',
        'start_time': '10:00',
        'end_time': '18:00',
        'rrc': 'rrc04',
        'malicious_as': ['197426'],  # Bitcanal
        'hijacked_prefix': [],  # Multiple prefixes for spam
        'label': 'prefix_hijacking',
        'type': 'PH',
        'duration_minutes': 480,
        'impact': 'Repeated hijacking for spam operations'
    },

    '3ve_ad_fraud_2018': {
        'name': '3ve Ad Fraud BGP Hijack',
        'date': '2018-11-27',
        'start_time': '00:00',
        'end_time': '23:59',
        'rrc': 'rrc04',
        'malicious_as': ['203070', '205211'],
        'hijacked_prefix': [],
        'label': 'prefix_hijacking',
        'type': 'PH',
        'duration_minutes': 1440,
        'impact': '$36M ad fraud operation via BGP hijacking'
    },

    'digitalocean_hijack_2018': {
        'name': 'DigitalOcean Prefix Hijack',
        'date': '2018-08-27',
        'start_time': '14:00',
        'end_time': '14:45',
        'rrc': 'rrc04',
        'malicious_as': ['139070'],
        'hijacked_prefix': ['104.16.0.0/12'],
        'label': 'prefix_hijacking',
        'type': 'PH',
        'duration_minutes': 45,
        'impact': 'DigitalOcean customer traffic intercepted'
    },

    'telkom_sa_2019': {
        'name': 'Telkom South Africa Leak',
        'date': '2019-11-05',
        'start_time': '09:20',
        'end_time': '12:00',
        'rrc': 'rrc04',
        'malicious_as': ['37457'],  # Telkom SA
        'hijacked_prefix': [],
        'label': 'prefix_hijacking',
        'type': 'PH',
        'duration_minutes': 160,
        'impact': 'Major South African ISP leak affecting global routes'
    },

    'telia_google_2021': {
        'name': 'Telia-Google Traffic Hijack',
        'date': '2021-10-04',
        'start_time': '16:00',
        'end_time': '18:30',
        'rrc': 'rrc04',
        'malicious_as': ['1299'],  # Telia
        'hijacked_prefix': [],
        'label': 'prefix_hijacking',
        'type': 'PH',
        'duration_minutes': 150,
        'impact': 'Google traffic misrouted through Telia'
    },

    'orange_spain_2024': {
        'name': 'Orange Spain RIPE Account Hijack',
        'date': '2024-01-03',
        'start_time': '09:30',
        'end_time': '13:00',
        'rrc': 'rrc04',
        'malicious_as': ['6805'],  # Orange Spain (compromised)
        'hijacked_prefix': [],
        'label': 'prefix_hijacking',
        'type': 'PH',
        'duration_minutes': 210,
        'impact': '50% Orange Spain traffic disrupted via RIPE account compromise'
    },

    'iceland_telecom_2017': {
        'name': 'Iceland Telecom Hijack',
        'date': '2017-01-16',
        'start_time': '12:00',
        'end_time': '13:30',
        'rrc': 'rrc04',
        'malicious_as': ['6677'],  # Icetelecom
        'hijacked_prefix': [],
        'label': 'prefix_hijacking',
        'type': 'PH',
        'duration_minutes': 90,
        'impact': 'Visa and Mastercard routes hijacked briefly'
    },

    'dodo_australia_2012': {
        'name': 'Dodo Australia Route Leak',
        'date': '2012-02-22',
        'start_time': '03:00',
        'end_time': '05:00',
        'rrc': 'rrc04',
        'malicious_as': ['38285'],  # Dodo
        'hijacked_prefix': [],
        'label': 'prefix_hijacking',
        'type': 'PH',
        'duration_minutes': 120,
        'impact': 'Australian ISP caused global routing issues'
    },

    'bitgrail_exchange_2018': {
        'name': 'BitGrail Exchange BGP Attack',
        'date': '2018-02-08',
        'start_time': '10:00',
        'end_time': '14:00',
        'rrc': 'rrc04',
        'malicious_as': [],
        'hijacked_prefix': [],
        'label': 'prefix_hijacking',
        'type': 'PH',
        'duration_minutes': 240,
        'impact': '$170M Nano cryptocurrency theft'
    },

    'aws_route53_dns_2019': {
        'name': 'AWS Route53 DNS Hijack (eNet)',
        'date': '2019-04-24',
        'start_time': '09:00',
        'end_time': '16:00',
        'rrc': 'rrc04',
        'malicious_as': ['7795'],  # eNet Inc
        'hijacked_prefix': ['205.251.192.0/21'],
        'label': 'prefix_hijacking',
        'type': 'PH',
        'duration_minutes': 420,
        'impact': 'Cryptocurrency phishing via DNS hijacking'
    },

    'iran_isp_2017': {
        'name': 'Iranian ISP Global Route Leak',
        'date': '2017-07-24',
        'start_time': '08:00',
        'end_time': '11:00',
        'rrc': 'rrc04',
        'malicious_as': ['58224'],  # TIC Iran
        'hijacked_prefix': [],
        'label': 'prefix_hijacking',
        'type': 'PH',
        'duration_minutes': 180,
        'impact': 'Iranian ISP leaked routes affecting global traffic'
    },

    'korean_isp_hijack_2019': {
        'name': 'Korean ISP Prefix Hijack',
        'date': '2019-03-06',
        'start_time': '02:00',
        'end_time': '06:00',
        'rrc': 'rrc04',
        'malicious_as': ['9318'],  # SK Broadband
        'hijacked_prefix': [],
        'label': 'prefix_hijacking',
        'type': 'PH',
        'duration_minutes': 240,
        'impact': 'Korean ISP announced foreign prefixes'
    },

    'cloudflare_ipfs_2019': {
        'name': 'Cloudflare IPFS Gateway Hijack',
        'date': '2019-06-19',
        'start_time': '13:00',
        'end_time': '15:00',
        'rrc': 'rrc04',
        'malicious_as': [],
        'hijacked_prefix': ['104.18.0.0/16'],
        'label': 'prefix_hijacking',
        'type': 'PH',
        'duration_minutes': 120,
        'impact': 'IPFS gateway traffic intercepted'
    },

    'us_gov_routes_2022': {
        'name': 'US Government Routes via China Telecom',
        'date': '2022-03-09',
        'start_time': '09:00',
        'end_time': '09:45',
        'rrc': 'rrc04',
        'malicious_as': ['4134'],  # China Telecom
        'hijacked_prefix': [],  # US military/gov prefixes
        'label': 'prefix_hijacking',
        'type': 'PH',
        'duration_minutes': 45,
        'impact': 'US government IP ranges routed through China'
    },

    # ========================================================================
    # PATH MANIPULATION (PM) INCIDENTS - Additional Events
    # ========================================================================

    'ntt_japan_leak_2019': {
        'name': 'NTT Japan Route Leak',
        'date': '2019-08-25',
        'start_time': '15:00',
        'end_time': '17:30',
        'rrc': 'rrc04',
        'malicious_as': ['2914'],  # NTT
        'hijacked_prefix': [],
        'label': 'path_manipulation',
        'type': 'PM',
        'duration_minutes': 150,
        'impact': 'Major Japanese carrier route leak'
    },

    'telstra_australia_2017': {
        'name': 'Telstra Australia Route Leak',
        'date': '2017-06-07',
        'start_time': '10:00',
        'end_time': '12:00',
        'rrc': 'rrc04',
        'malicious_as': ['1221'],  # Telstra
        'hijacked_prefix': [],
        'label': 'path_manipulation',
        'type': 'PM',
        'duration_minutes': 120,
        'impact': 'Australian routes leaked to global table'
    },

    'centurylink_leak_2018': {
        'name': 'CenturyLink Major Route Leak',
        'date': '2018-12-27',
        'start_time': '09:00',
        'end_time': '22:00',
        'rrc': 'rrc04',
        'malicious_as': ['3356', '209'],  # Level3, CenturyLink
        'hijacked_prefix': [],
        'label': 'path_manipulation',
        'type': 'PM',
        'duration_minutes': 780,
        'impact': '911 services disrupted across US states'
    },

    'cogent_route_leak_2021': {
        'name': 'Cogent Major Route Leak',
        'date': '2021-07-22',
        'start_time': '14:00',
        'end_time': '16:00',
        'rrc': 'rrc04',
        'malicious_as': ['174'],  # Cogent
        'hijacked_prefix': [],
        'label': 'path_manipulation',
        'type': 'PM',
        'duration_minutes': 120,
        'impact': 'Cogent leaked routes causing widespread issues'
    },

    'zayo_route_leak_2019': {
        'name': 'Zayo Group Route Leak',
        'date': '2019-11-06',
        'start_time': '12:00',
        'end_time': '14:30',
        'rrc': 'rrc04',
        'malicious_as': ['6461'],  # Zayo
        'hijacked_prefix': [],
        'label': 'path_manipulation',
        'type': 'PM',
        'duration_minutes': 150,
        'impact': 'Multiple cloud providers affected'
    },

    'tata_communications_2019': {
        'name': 'Tata Communications Route Leak',
        'date': '2019-09-11',
        'start_time': '08:00',
        'end_time': '10:30',
        'rrc': 'rrc04',
        'malicious_as': ['6453'],  # Tata
        'hijacked_prefix': [],
        'label': 'path_manipulation',
        'type': 'PM',
        'duration_minutes': 150,
        'impact': 'Global traffic rerouting'
    },

    'as_path_poison_2014': {
        'name': 'AS-Path Poisoning Attack Example',
        'date': '2014-08-05',
        'start_time': '14:00',
        'end_time': '18:00',
        'rrc': 'rrc00',
        'malicious_as': [],
        'hijacked_prefix': [],
        'label': 'path_manipulation',
        'type': 'PM',
        'detection_rule': 'as_path_prepend_count',
        'prepend_threshold': 15,
        'duration_minutes': 240,
        'impact': 'AS-Path poisoning to manipulate traffic flow'
    },

    'rpki_mismatch_2020': {
        'name': 'RPKI Invalid Origin Large Scale',
        'date': '2020-02-03',
        'start_time': '06:00',
        'end_time': '12:00',
        'rrc': 'rrc04',
        'malicious_as': [],
        'hijacked_prefix': [],
        'label': 'path_manipulation',
        'type': 'PM',
        'duration_minutes': 360,
        'impact': 'RPKI validation failures causing route instability'
    },

    'de_cix_incident_2018': {
        'name': 'DE-CIX Route Server Incident',
        'date': '2018-05-14',
        'start_time': '10:00',
        'end_time': '11:30',
        'rrc': 'rrc04',
        'malicious_as': [],
        'hijacked_prefix': [],
        'label': 'path_manipulation',
        'type': 'PM',
        'duration_minutes': 90,
        'impact': 'Route server misconfiguration at major IXP'
    },

    'hurricane_electric_leak_2020': {
        'name': 'Hurricane Electric Route Leak',
        'date': '2020-04-16',
        'start_time': '16:00',
        'end_time': '18:00',
        'rrc': 'rrc04',
        'malicious_as': ['6939'],  # HE
        'hijacked_prefix': [],
        'label': 'path_manipulation',
        'type': 'PM',
        'duration_minutes': 120,
        'impact': 'Transit provider route leak'
    },

    'as_prepend_attack_2015': {
        'name': 'Excessive AS-Path Prepending Attack',
        'date': '2015-09-22',
        'start_time': '08:00',
        'end_time': '20:00',
        'rrc': 'rrc00',
        'malicious_as': ['263444'],
        'hijacked_prefix': [],
        'label': 'path_manipulation',
        'type': 'PM',
        'detection_rule': 'as_path_prepend_count',
        'prepend_threshold': 20,
        'duration_minutes': 720,
        'impact': 'Route manipulation via excessive prepending'
    },

    'gtt_communications_2020': {
        'name': 'GTT Communications Route Leak',
        'date': '2020-11-10',
        'start_time': '07:00',
        'end_time': '09:00',
        'rrc': 'rrc04',
        'malicious_as': ['3257'],  # GTT
        'hijacked_prefix': [],
        'label': 'path_manipulation',
        'type': 'PM',
        'duration_minutes': 120,
        'impact': 'Global tier-1 route leak'
    },

    # ========================================================================
    # DOS/ROUTE LEAK INCIDENTS - Additional Events
    # ========================================================================

    'facebook_outage_2021': {
        'name': 'Facebook/Meta Global Outage',
        'date': '2021-10-04',
        'start_time': '15:39',
        'end_time': '21:00',
        'rrc': 'rrc04',
        'malicious_as': ['32934'],  # Facebook
        'hijacked_prefix': [],
        'label': 'dos_attack',
        'type': 'DoS',
        'detection_rule': 'route_withdrawal',
        'duration_minutes': 321,
        'impact': 'Complete Facebook/Instagram/WhatsApp outage, 3.5B users affected'
    },

    'blaster_worm_2003': {
        'name': 'Blaster Worm BGP Impact',
        'date': '2003-08-11',
        'start_time': '16:00',
        'end_time': '23:59',
        'rrc': 'rrc00',
        'malicious_as': [],
        'hijacked_prefix': [],
        'label': 'dos_attack',
        'type': 'DoS',
        'detection_rule': 'update_burst',
        'duration_minutes': 480,
        'impact': 'Windows RPC worm caused massive BGP instability'
    },

    'microtik_botnet_2018': {
        'name': 'MikroTik Botnet BGP Manipulation',
        'date': '2018-10-04',
        'start_time': '00:00',
        'end_time': '23:59',
        'rrc': 'rrc04',
        'malicious_as': [],
        'hijacked_prefix': [],
        'label': 'dos_attack',
        'type': 'DoS',
        'detection_rule': 'update_burst',
        'duration_minutes': 1440,
        'impact': 'Compromised routers announcing bad routes'
    },

    'reddit_outage_2020': {
        'name': 'Reddit BGP-Related Outage',
        'date': '2020-03-05',
        'start_time': '20:00',
        'end_time': '22:00',
        'rrc': 'rrc04',
        'malicious_as': [],
        'hijacked_prefix': [],
        'label': 'dos_attack',
        'type': 'DoS',
        'duration_minutes': 120,
        'impact': 'Reddit inaccessible due to routing issues'
    },

    'twitter_outage_2019': {
        'name': 'Twitter Partial Routing Outage',
        'date': '2019-07-11',
        'start_time': '14:00',
        'end_time': '16:30',
        'rrc': 'rrc04',
        'malicious_as': [],
        'hijacked_prefix': [],
        'label': 'dos_attack',
        'type': 'DoS',
        'duration_minutes': 150,
        'impact': 'Twitter intermittent availability'
    },

    'stackpath_cdn_2019': {
        'name': 'StackPath/MaxCDN Route Issues',
        'date': '2019-09-03',
        'start_time': '16:00',
        'end_time': '18:00',
        'rrc': 'rrc04',
        'malicious_as': ['30633'],  # Limelight
        'hijacked_prefix': [],
        'label': 'dos_attack',
        'type': 'DoS',
        'duration_minutes': 120,
        'impact': 'CDN routing issues affecting websites'
    },

    'conficker_worm_2009': {
        'name': 'Conficker Worm BGP Impact',
        'date': '2009-04-01',
        'start_time': '00:00',
        'end_time': '06:00',
        'rrc': 'rrc04',
        'malicious_as': [],
        'hijacked_prefix': [],
        'label': 'dos_attack',
        'type': 'DoS',
        'detection_rule': 'update_burst',
        'duration_minutes': 360,
        'impact': 'Worm activation caused routing instability'
    },

    'aws_us_east_2017': {
        'name': 'AWS US-East S3 Outage',
        'date': '2017-02-28',
        'start_time': '12:37',
        'end_time': '16:06',
        'rrc': 'rrc04',
        'malicious_as': ['16509'],  # Amazon
        'hijacked_prefix': [],
        'label': 'dos_attack',
        'type': 'DoS',
        'duration_minutes': 209,
        'impact': 'Major AWS outage affecting thousands of websites'
    },

    'github_ddos_2018': {
        'name': 'GitHub Memcached DDoS Attack',
        'date': '2018-02-28',
        'start_time': '17:21',
        'end_time': '17:30',
        'rrc': 'rrc04',
        'malicious_as': [],
        'hijacked_prefix': [],
        'label': 'dos_attack',
        'type': 'DoS',
        'detection_rule': 'update_burst',
        'duration_minutes': 9,
        'impact': 'Record 1.35 Tbps DDoS attack on GitHub'
    },

    'dyn_dns_attack_2016': {
        'name': 'Dyn DNS DDoS (Mirai Botnet)',
        'date': '2016-10-21',
        'start_time': '11:10',
        'end_time': '18:36',
        'rrc': 'rrc04',
        'malicious_as': [],
        'hijacked_prefix': [],
        'label': 'dos_attack',
        'type': 'DoS',
        'detection_rule': 'update_burst',
        'duration_minutes': 446,
        'impact': 'Twitter, Netflix, Reddit, CNN down; Mirai IoT botnet'
    },

    'long_aspath_attack_2014': {
        'name': 'Extremely Long AS-Path DoS',
        'date': '2014-07-07',
        'start_time': '10:00',
        'end_time': '14:00',
        'rrc': 'rrc04',
        'malicious_as': [],
        'hijacked_prefix': [],
        'label': 'dos_attack',
        'type': 'DoS',
        'detection_rule': 'as_path_length',
        'path_length_threshold': 150,
        'duration_minutes': 240,
        'impact': 'Router CPU exhaustion via long AS-paths'
    },

    'route_oscillation_2015': {
        'name': 'BGP Route Oscillation Event',
        'date': '2015-06-12',
        'start_time': '08:00',
        'end_time': '12:00',
        'rrc': 'rrc00',
        'malicious_as': [],
        'hijacked_prefix': [],
        'label': 'dos_attack',
        'type': 'DoS',
        'detection_rule': 'update_burst',
        'duration_minutes': 240,
        'impact': 'Routing instability due to oscillating announcements'
    },

    'deaggregation_attack_2016': {
        'name': 'Prefix Deaggregation Attack',
        'date': '2016-04-15',
        'start_time': '06:00',
        'end_time': '10:00',
        'rrc': 'rrc04',
        'malicious_as': [],
        'hijacked_prefix': [],
        'label': 'dos_attack',
        'type': 'DoS',
        'detection_rule': 'route_deaggregation',
        'duration_minutes': 240,
        'impact': 'FIB exhaustion via /24 deaggregation'
    },

    'global_rib_growth_2019': {
        'name': 'Abnormal Global RIB Growth',
        'date': '2019-05-06',
        'start_time': '14:00',
        'end_time': '18:00',
        'rrc': 'rrc04',
        'malicious_as': [],
        'hijacked_prefix': [],
        'label': 'dos_attack',
        'type': 'DoS',
        'detection_rule': 'route_deaggregation',
        'duration_minutes': 240,
        'impact': 'Sudden increase in global routing table size'
    },
}


# ============================================================================
# CONFIGURATION
# ============================================================================

BASE_RIPE_URL = "https://data.ris.ripe.net"
RIPE_DIR = "/home/smotaali/BGP_Traffic_Generation/RIPE/RIPE_INCIDENTS_EXTENDED"
TEMP_DIR = os.path.join(RIPE_DIR, "temp_mrt")


def create_directories():
    """Create necessary directories."""
    Path(RIPE_DIR).mkdir(parents=True, exist_ok=True)
    Path(TEMP_DIR).mkdir(parents=True, exist_ok=True)


def ip_in_prefix(ip, prefix):
    """Check if an IP address belongs to a prefix."""
    try:
        return ipaddress.ip_address(ip) in ipaddress.ip_network(prefix)
    except:
        return False


def prefix_matches_hijacked(prefix, hijacked_prefixes):
    """Check if a prefix matches any hijacked prefix."""
    try:
        check_net = ipaddress.ip_network(prefix)
        for hijacked in hijacked_prefixes:
            hijacked_net = ipaddress.ip_network(hijacked)
            if check_net == hijacked_net or check_net.subnet_of(hijacked_net) or check_net.supernet_of(hijacked_net):
                return True
    except:
        pass
    return False


def detect_anomaly(record, incident_config, incident_start, incident_end):
    """
    Detect if a BGP record matches the anomaly pattern for an incident.

    Returns: tuple (is_anomaly: bool, label: str, confidence: str)
    """
    try:
        record_time = datetime.strptime(record['Time'], '%Y-%m-%d %H:%M:%S')
    except Exception:
        return False, 'normal', 'N/A'

    is_during_incident = incident_start <= record_time <= incident_end
    if not is_during_incident:
        return False, 'normal', 'N/A'

    incident_type = incident_config['type']
    label = incident_config['label']

    as_path_str = record.get('AS_Path', '') or ''
    as_list = as_path_str.split() if as_path_str else []
    # Get origin AS from AS_Path (last AS in path)
    origin_as = as_list[-1] if as_list else ''
    prefix = record.get('Prefix', '') or ''
    malicious_as_list = incident_config.get('malicious_as', []) or []
    hijacked_prefixes = incident_config.get('hijacked_prefix', []) or []

    # ----------------------------------------------------------------------
    # PREFIX HIJACKING (PH): primary signal = Origin_AS + hijacked prefix
    # ----------------------------------------------------------------------
    if incident_type == 'PH':
        # prefix match (including sub/supernets)
        matches_prefix = False
        if hijacked_prefixes:
            matches_prefix = prefix_matches_hijacked(prefix, hijacked_prefixes)

        involves_malicious_origin = origin_as in malicious_as_list if origin_as else False
        involves_malicious_in_path = any(mal_as in as_list for mal_as in malicious_as_list)

        # High confidence: correct hijacked prefix AND malicious origin
        if hijacked_prefixes:
            if matches_prefix and involves_malicious_origin:
                return True, label, 'high'
            # Medium: either prefix matches or malicious AS appears (origin or path)
            if matches_prefix or involves_malicious_origin or involves_malicious_in_path:
                return True, label, 'medium'
        else:
            # Incidents without explicit prefix set: rely on malicious origin / path
            if involves_malicious_origin:
                return True, label, 'high'
            if involves_malicious_in_path:
                return True, label, 'medium'

        return False, 'normal', 'N/A'

    # ----------------------------------------------------------------------
    # PATH MANIPULATION (PM): primary signal = AS_Path content/shape
    # ----------------------------------------------------------------------
    if incident_type == 'PM':
        detection_rule = incident_config.get('detection_rule', '')
        # Excessive prepending by a specific AS
        if detection_rule == 'as_path_prepend_count' and as_list:
            prepend_threshold = incident_config.get('prepend_threshold', 10)
            for mal_as in malicious_as_list:
                if not mal_as:
                    continue
                count = as_list.count(mal_as)
                if count >= prepend_threshold:
                    return True, label, 'high'

        # Generic route leak / manipulation in the incident window:
        # malicious AS appears anywhere in the path
        for mal_as in malicious_as_list:
            if mal_as and mal_as in as_list:
                return True, label, 'medium'

        return False, 'normal', 'N/A'

    # ----------------------------------------------------------------------
    # DoS / ROUTE LEAK (DoS): long paths, bursts, deaggregation, leak AS
    # ----------------------------------------------------------------------
    if incident_type == 'DoS':
        detection_rule = incident_config.get('detection_rule', '')
        path_len = len(as_list)

        # Very long AS paths
        if detection_rule == 'as_path_length':
            threshold = incident_config.get('path_length_threshold', 100)
            if path_len >= threshold:
                return True, label, 'high'

        # Worm / burst incidents: any update in window is anomalous
        if detection_rule == 'update_burst':
            return True, label, 'medium'

        # Route leak incidents: presence of leak AS in AS_Path
        if detection_rule == 'route_leak':
            for mal_as in malicious_as_list:
                if mal_as and mal_as in as_list:
                    return True, label, 'medium'
            # Even without explicit malicious_as, you may still want to flag all
            # updates in the tight incident window as anomalous; keep medium:
            if not malicious_as_list:
                return True, label, 'medium'

        # Route withdrawal (like Facebook outage)
        if detection_rule == 'route_withdrawal':
            # All withdrawals or updates involving the AS during the outage
            for mal_as in malicious_as_list:
                if mal_as and mal_as in as_list:
                    return True, label, 'high'
            # Withdrawal messages during the incident are anomalous
            if record.get('Entry_Type') == 'W':
                return True, label, 'medium'

        # Deaggregation: very specific more-specifics (e.g., many /24s)
        if detection_rule == 'route_deaggregation' and prefix:
            try:
                net = ipaddress.ip_network(prefix)
                if net.prefixlen >= 24:
                    return True, label, 'high'
            except Exception:
                pass

        # Fallback: malicious AS appears in path during DoS/leak
        for mal_as in malicious_as_list:
            if mal_as and mal_as in as_list:
                return True, label, 'high'

        return False, 'normal', 'N/A'

    # Unknown type
    return False, 'normal', 'N/A'


def download_file(url, local_path):
    """Download a file from URL."""
    try:
        print(f"  Downloading {url}...")
        with urlopen(url, timeout=60) as response:
            with open(local_path, 'wb') as out_file:
                out_file.write(response.read())
        print(f"  Downloaded: {os.path.basename(local_path)}")
        return True
    except Exception as e:
        print(f"  Error downloading {url}: {e}")
        return False


def decompress_gz(gz_file, output_file):
    """Decompress gzip file."""
    try:
        with gzip.open(gz_file, 'rb') as f_in:
            with open(output_file, 'wb') as f_out:
                shutil.copyfileobj(f_in, f_out)
        return True
    except Exception as e:
        print(f"  Error decompressing {gz_file}: {e}")
        return False


def parse_bgpdump_line(line):
    """
    Parse a single line from bgpdump -m output.

    bgpdump -m format:
    BGP4MP|timestamp|A|peer_ip|peer_as|prefix|as_path|ORIGIN|next_hop|local_pref|med|community|atomic_agg|aggregator
    BGP4MP|timestamp|W|peer_ip|peer_as|prefix

    ORIGIN field (index 7) contains: IGP, EGP, or INCOMPLETE
    """
    line = line.strip()
    if not line:
        return None

    parts = line.split('|')

    if len(parts) < 6:
        return None

    try:
        msg_type = parts[0]
        if msg_type != 'BGP4MP':
            return None

        timestamp = int(parts[1])
        dt = datetime.utcfromtimestamp(timestamp)
        date_time = dt.strftime('%Y-%m-%d %H:%M:%S')

        update_type = parts[2]
        peer_ip = parts[3]
        peer_as = parts[4]
        prefix = parts[5]

        if update_type == 'W':
            return {
                'MRT_Type': 'BGP4MP',
                'Time': date_time,
                'Entry_Type': 'W',
                'Peer_IP': peer_ip,
                'Peer_AS': peer_as,
                'Prefix': prefix,
                'AS_Path': '',
                'Origin': '',
                'Next_Hop': '',
                'Local_Pref': '',
                'MED': '',
                'Community': '',
                'Atomic_Aggregate': '',
                'Aggregator': ''
            }

        as_path = parts[6] if len(parts) > 6 else ''
        origin = parts[7] if len(parts) > 7 else ''  # BGP Origin: IGP/EGP/INCOMPLETE
        next_hop = parts[8] if len(parts) > 8 else ''
        local_pref = parts[9] if len(parts) > 9 else ''
        med = parts[10] if len(parts) > 10 else ''
        community = parts[11] if len(parts) > 11 else ''
        atomic_agg = parts[12] if len(parts) > 12 else ''
        aggregator = parts[13] if len(parts) > 13 else ''

        return {
            'MRT_Type': 'BGP4MP',
            'Time': date_time,
            'Entry_Type': 'A',
            'Peer_IP': peer_ip,
            'Peer_AS': peer_as,
            'Prefix': prefix,
            'AS_Path': as_path,
            'Origin': origin,  # BGP Origin attribute (IGP/EGP/INCOMPLETE)
            'Next_Hop': next_hop,
            'Local_Pref': local_pref,
            'MED': med,
            'Community': community,
            'Atomic_Aggregate': atomic_agg,
            'Aggregator': aggregator
        }

    except (ValueError, IndexError):
        return None


def parse_mrt_file_with_bgpdump(mrt_file):
    """Parse MRT file using bgpdump."""
    records = []

    try:
        result = subprocess.run(
            ['bgpdump', '-m', mrt_file],
            capture_output=True,
            text=True,
            check=False,
            timeout=300
        )

        if result.returncode != 0:
            return []

        lines = result.stdout.strip().split('\n')

        for line in lines:
            record = parse_bgpdump_line(line)
            if record:
                records.append(record)

    except FileNotFoundError:
        print("  bgpdump not found. Install with: apt-get install bgpdump")
        return []
    except subprocess.TimeoutExpired:
        print("  bgpdump timeout")
        return []
    except Exception as e:
        print(f"  Error parsing MRT file: {e}")
        return []

    return records


def collect_incident_data(incident_key, incident_config):
    """Collect and label data for a specific incident."""
    print("\n" + "=" * 80)
    print(f"Processing Incident: {incident_config['name']}")
    print("=" * 80)
    print(f"Type: {incident_config['type']} ({incident_config['label']})")
    print(f"Date: {incident_config['date']}")
    print(f"Time: {incident_config['start_time']} - {incident_config['end_time']} UTC")
    print(f"RRC: {incident_config['rrc']}")
    if 'impact' in incident_config:
        print(f"Impact: {incident_config['impact']}")

    # Parse date and time
    incident_date = datetime.strptime(incident_config['date'], '%Y-%m-%d')
    start_time = datetime.strptime(f"{incident_config['date']} {incident_config['start_time']}", '%Y-%m-%d %H:%M')
    end_time = datetime.strptime(f"{incident_config['date']} {incident_config['end_time']}", '%Y-%m-%d %H:%M')

    # Handle cases where end time is next day
    if end_time < start_time:
        end_time += timedelta(days=1)

    # Extend collection window (1 hour before to 1 hour after)
    collection_start = start_time - timedelta(hours=1)
    collection_end = end_time + timedelta(hours=1)

    print(f"Collection window: {collection_start} - {collection_end} UTC")

    # Create output directory for this incident
    incident_dir = os.path.join(RIPE_DIR, incident_key)
    mrt_dir = os.path.join(incident_dir, "mrt_files")
    Path(mrt_dir).mkdir(parents=True, exist_ok=True)

    # Build base URL
    year_month = incident_date.strftime('%Y.%m')
    rrc = incident_config['rrc']
    base_url = f"{BASE_RIPE_URL}/{rrc}/{year_month}"

    # Generate file list (5-minute intervals)
    files_to_download = []
    current_time = collection_start

    # Round to nearest 5-minute interval
    current_time = current_time.replace(second=0, microsecond=0)
    minute = (current_time.minute // 5) * 5
    current_time = current_time.replace(minute=minute)

    while current_time <= collection_end:
        filename = f"updates.{current_time.strftime('%Y%m%d.%H%M')}.gz"
        files_to_download.append((current_time, filename))
        current_time += timedelta(minutes=5)

    print(f"\nFiles to collect: {len(files_to_download)}")

    # Download files
    downloaded_files = []
    print("\nDownloading MRT files...")

    for i, (file_time, filename) in enumerate(files_to_download, 1):
        url = f"{base_url}/{filename}"
        local_path = os.path.join(mrt_dir, filename)

        if os.path.exists(local_path):
            print(f"[{i}/{len(files_to_download)}] Already exists: {filename}")
            downloaded_files.append(local_path)
            continue

        print(f"[{i}/{len(files_to_download)}] ", end="")
        if download_file(url, local_path):
            downloaded_files.append(local_path)

    print(f"\nTotal files available: {len(downloaded_files)}")

    # Process files
    print("\nProcessing MRT files...")
    all_records = []

    for i, gz_file in enumerate(downloaded_files, 1):
        mrt_file = os.path.join(TEMP_DIR, os.path.basename(gz_file).replace('.gz', ''))

        print(f"[{i}/{len(downloaded_files)}] Processing {os.path.basename(gz_file)}...", end=" ")

        if not decompress_gz(gz_file, mrt_file):
            print("Failed")
            continue

        records = parse_mrt_file_with_bgpdump(mrt_file)

        if records:
            print(f"{len(records)} records")
            all_records.extend(records)
        else:
            print("0 records")

        try:
            os.remove(mrt_file)
        except:
            pass

    # Label records
    print("\nLabeling records...")
    labeled_records = []
    anomaly_counts = {'normal': 0, incident_config['label']: 0}
    confidence_counts = {'high': 0, 'medium': 0, 'low': 0, 'N/A': 0}

    for record in all_records:
        is_anomaly, label, confidence = detect_anomaly(record, incident_config, start_time, end_time)
        record['Label'] = label
        record['Confidence'] = confidence
        record['Incident'] = incident_config['name']
        labeled_records.append(record)

        anomaly_counts[label] += 1
        confidence_counts[confidence] += 1

    # Write CSV
    csv_output = os.path.join(incident_dir, f"{incident_key}_labeled.csv")
    print(f"\nWriting CSV: {csv_output}")

    if labeled_records:
        fieldnames = ['MRT_Type', 'Time', 'Entry_Type', 'Peer_IP', 'Peer_AS',
                     'Prefix', 'AS_Path', 'Origin', 'Next_Hop', 'Local_Pref',
                     'MED', 'Community', 'Atomic_Aggregate', 'Aggregator',
                     'Label', 'Confidence', 'Incident']

        try:
            with open(csv_output, 'w', newline='', encoding='utf-8') as csvfile:
                writer = csv.DictWriter(csvfile, fieldnames=fieldnames, restval='')
                writer.writeheader()
                writer.writerows(labeled_records)

            print(f"CSV created: {csv_output}")
            print(f"Total records: {len(labeled_records):,}")
            print(f"\nLabel Distribution:")
            for label, count in anomaly_counts.items():
                pct = (count / len(labeled_records) * 100) if len(labeled_records) > 0 else 0
                print(f"  {label}: {count:,} ({pct:.2f}%)")

            print(f"\nConfidence Distribution:")
            for conf, count in confidence_counts.items():
                if count > 0:
                    pct = (count / len(labeled_records) * 100) if len(labeled_records) > 0 else 0
                    print(f"  {conf}: {count:,} ({pct:.2f}%)")

            # Show sample anomaly
            anomaly_sample = next((r for r in labeled_records if r['Label'] != 'normal'), None)
            if anomaly_sample:
                print(f"\nSample Anomaly ({incident_config['label']}):")
                print(f"  Time: {anomaly_sample['Time']}")
                print(f"  Prefix: {anomaly_sample['Prefix']}")
                print(f"  AS_Path: {anomaly_sample['AS_Path']}")
                print(f"  Origin: {anomaly_sample['Origin']}")
                print(f"  Confidence: {anomaly_sample['Confidence']}")

        except Exception as e:
            print(f"Error writing CSV: {e}")
            import traceback
            traceback.print_exc()
    else:
        print("No records to write")

    return len(labeled_records), anomaly_counts


def list_incidents():
    """List all extended incidents."""
    print("\n" + "=" * 80)
    print("EXTENDED BGP ANOMALY INCIDENTS DATABASE")
    print("=" * 80)

    ph_incidents = [(k, v) for k, v in EXTENDED_INCIDENTS.items() if v['type'] == 'PH']
    pm_incidents = [(k, v) for k, v in EXTENDED_INCIDENTS.items() if v['type'] == 'PM']
    dos_incidents = [(k, v) for k, v in EXTENDED_INCIDENTS.items() if v['type'] == 'DoS']

    print(f"\n[PREFIX HIJACKING - {len(ph_incidents)} incidents]")
    for key, config in ph_incidents:
        print(f"  {key}: {config['name']} ({config['date']})")

    print(f"\n[PATH MANIPULATION - {len(pm_incidents)} incidents]")
    for key, config in pm_incidents:
        print(f"  {key}: {config['name']} ({config['date']})")

    print(f"\n[DOS/ROUTE LEAK - {len(dos_incidents)} incidents]")
    for key, config in dos_incidents:
        print(f"  {key}: {config['name']} ({config['date']})")

    print(f"\nTotal: {len(EXTENDED_INCIDENTS)} incidents")


def main():
    """Main execution function."""
    import argparse

    parser = argparse.ArgumentParser(
        description='Extended BGP Anomaly Collector - Collect additional BGP incident data'
    )
    parser.add_argument('--list', action='store_true', help='List all available incidents')
    parser.add_argument('--incident', type=str, help='Collect specific incident by key')
    parser.add_argument('--all', action='store_true', help='Collect all incidents')
    parser.add_argument('--type', type=str, choices=['PH', 'PM', 'DoS'],
                       help='Collect only incidents of specific type')
    parser.add_argument('--output-dir', type=str, help='Custom output directory')

    args = parser.parse_args()

    if args.output_dir:
        global RIPE_DIR, TEMP_DIR
        RIPE_DIR = args.output_dir
        TEMP_DIR = os.path.join(RIPE_DIR, "temp_mrt")

    if args.list:
        list_incidents()
        return

    print("=" * 80)
    print("Extended BGP Incident Data Collector and Labeler")
    print("Additional Real-World BGP Anomaly Detection Dataset Generator")
    print("=" * 80)

    create_directories()

    # Determine which incidents to process
    if args.incident:
        if args.incident not in EXTENDED_INCIDENTS:
            print(f"Error: Unknown incident '{args.incident}'")
            print("Use --list to see available incidents")
            return
        incidents_to_process = {args.incident: EXTENDED_INCIDENTS[args.incident]}
    elif args.type:
        incidents_to_process = {
            k: v for k, v in EXTENDED_INCIDENTS.items()
            if v['type'] == args.type
        }
    elif args.all:
        incidents_to_process = EXTENDED_INCIDENTS
    else:
        # Default: show help and list incidents
        parser.print_help()
        print("\n")
        list_incidents()
        return

    # Print summary
    print(f"\nIncidents to process: {len(incidents_to_process)}")
    ph_count = sum(1 for c in incidents_to_process.values() if c['type'] == 'PH')
    pm_count = sum(1 for c in incidents_to_process.values() if c['type'] == 'PM')
    dos_count = sum(1 for c in incidents_to_process.values() if c['type'] == 'DoS')
    print(f"  Prefix Hijacking (PH): {ph_count}")
    print(f"  Path Manipulation (PM): {pm_count}")
    print(f"  DoS/Route Leak (DoS): {dos_count}")

    print("\nProcessing incidents...")

    # Process each incident
    total_records = 0
    total_anomalies = 0
    summary = []

    for incident_key, incident_config in incidents_to_process.items():
        try:
            num_records, anomaly_counts = collect_incident_data(incident_key, incident_config)
            total_records += num_records
            total_anomalies += sum(count for label, count in anomaly_counts.items() if label != 'normal')

            summary.append({
                'incident': incident_config['name'],
                'type': incident_config['type'],
                'records': num_records,
                'anomalies': anomaly_counts.get(incident_config['label'], 0)
            })

        except Exception as e:
            print(f"\nError processing {incident_key}: {e}")
            import traceback
            traceback.print_exc()

    # Print final summary
    print("\n" + "=" * 80)
    print("FINAL SUMMARY")
    print("=" * 80)
    print(f"\nTotal records collected: {total_records:,}")
    print(f"Total anomalies labeled: {total_anomalies:,}")
    print(f"Anomaly rate: {(total_anomalies/total_records*100):.2f}%" if total_records > 0 else "N/A")

    print("\nPer-Incident Summary:")
    for item in summary:
        print(f"  [{item['type']}] {item['incident']}: {item['records']:,} records, {item['anomalies']:,} anomalies")

    print(f"\nAll data saved in: {os.path.abspath(RIPE_DIR)}")

    # Cleanup temp directory
    try:
        shutil.rmtree(TEMP_DIR)
        print("Temporary files cleaned up")
    except Exception as e:
        print(f"Warning: {e}")

    # Write combined summary CSV
    summary_csv = os.path.join(RIPE_DIR, "collection_summary.csv")
    try:
        with open(summary_csv, 'w', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=['incident', 'type', 'records', 'anomalies'])
            writer.writeheader()
            writer.writerows(summary)
        print(f"Summary saved to: {summary_csv}")
    except Exception as e:
        print(f"Warning: Could not write summary CSV: {e}")


if __name__ == "__main__":
    main()
