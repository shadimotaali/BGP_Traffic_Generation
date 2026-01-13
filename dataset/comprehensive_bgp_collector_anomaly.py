#!/usr/bin/env python3
"""
Enhanced script to collect RIPE RRC BGP update packets for multiple historical
incidents and label them according to attack type.

Includes 30+ real-world BGP anomalies (prefix hijacking, path manipulation, DoS)
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
# INCIDENT DEFINITIONS - Comprehensive BGP Anomaly Events Database
# ============================================================================

INCIDENTS = {
    # ========================================================================
    # PREFIX HIJACKING (PH) INCIDENTS
    # ========================================================================
    
    'pakistan_youtube': {
        'name': 'Pakistan-YouTube Hijack',
        'date': '2008-02-24',
        'start_time': '18:47',
        'end_time': '21:01',
        'rrc': 'rrc04',
        'malicious_as': ['17557'],
        'hijacked_prefix': ['208.65.153.0/24'],
        'label': 'prefix_hijacking',
        'type': 'PH',
        'duration_minutes': 134
    },
    
    'quad101': {
        'name': 'Quad101 Hijack',
        'date': '2019-05-08',
        'start_time': '15:08',
        'end_time': '15:15',
        'rrc': 'rrc04',
        'malicious_as': ['268869'],
        'hijacked_prefix': ['101.101.101.0/24'],
        'label': 'prefix_hijacking',
        'type': 'PH',
        'duration_minutes': 7
    },
    
    'rostelecom': {
        'name': 'Rostelecom Route Leak',
        'date': '2020-04-01',
        'start_time': '19:28',
        'end_time': '20:30',
        'rrc': 'rrc04',
        'malicious_as': ['12389'],
        'hijacked_prefix': [],  # 8800+ prefixes
        'label': 'prefix_hijacking',
        'type': 'PH',
        'duration_minutes': 62
    },
    
    'klayswap': {
        'name': 'KlaySwap BGP Hijack',
        'date': '2022-02-03',
        'start_time': '10:04',
        'end_time': '13:00',
        'rrc': 'rrc04',
        'malicious_as': ['9457'],
        'hijacked_prefix': ['211.249.216.0/21'],
        'label': 'prefix_hijacking',
        'type': 'PH',
        'duration_minutes': 176,
        'impact': '$1.9M cryptocurrency theft'
    },
    
    'mainone_google': {
        'name': 'MainOne-Google Hijack',
        'date': '2018-11-12',
        'start_time': '21:10',
        'end_time': '22:35',
        'rrc': 'rrc04',
        'malicious_as': ['37282', '4809', '20485'],  # MainOne, China Telecom, TransTelecom
        'hijacked_prefix': [],  # 212 Google prefixes
        'label': 'prefix_hijacking',
        'type': 'PH',
        'duration_minutes': 85,
        'impact': 'Google global disruption, traffic via Russia/China'
    },
    
    'amazon_route53': {
        'name': 'Amazon Route 53 Hijack (MyEtherWallet)',
        'date': '2018-04-24',
        'start_time': '11:05',
        'end_time': '12:55',
        'rrc': 'rrc04',
        'malicious_as': ['10297', '6939', '8560'],  # eNET, Hurricane Electric, 1&1
        'hijacked_prefix': ['205.251.192.0/23', '205.251.194.0/23', '205.251.196.0/23', '205.251.198.0/23'],
        'label': 'prefix_hijacking',
        'type': 'PH',
        'duration_minutes': 110,
        'impact': '$235K+ cryptocurrency theft'
    },
    
    'rostelecom_financial': {
        'name': 'Rostelecom Financial Services Hijack',
        'date': '2017-04-06',
        'start_time': '14:30',
        'end_time': '14:37',
        'rrc': 'rrc04',
        'malicious_as': ['12389'],
        'hijacked_prefix': [],  # 50+ financial institution prefixes
        'label': 'prefix_hijacking',
        'type': 'PH',
        'duration_minutes': 7,
        'impact': 'MasterCard, Visa, 20+ financial institutions'
    },
    
    'dvlink_hijack': {
        'name': 'DV-LINK Russian BGP Hijack',
        'date': '2017-12-18',
        'start_time': '10:30',
        'end_time': '10:33',
        'rrc': 'rrc04',
        'malicious_as': ['39523'],  # DV-LINK-AS
        'hijacked_prefix': [],  # 80 high-traffic prefixes
        'label': 'prefix_hijacking',
        'type': 'PH',
        'duration_minutes': 3,
        'impact': 'Google, Apple, Facebook, Microsoft, Twitch, NTT, Riot Games'
    },
    
    'bharti_airtel': {
        'name': 'Bharti Airtel Route Leak',
        'date': '2015-11-06',
        'start_time': '00:00',
        'end_time': '09:00',
        'rrc': 'rrc04',
        'malicious_as': ['9498'],  # Bharti Airtel
        'hijacked_prefix': [],  # 16,123 Level 3 customer prefixes (8.0.0.0/8)
        'label': 'prefix_hijacking',
        'type': 'PH',
        'duration_minutes': 540,
        'impact': '2000+ AS networks affected, global impact'
    },
    
    'hathway_google': {
        'name': 'Hathway-Google Leak',
        'date': '2015-03-11',
        'start_time': '10:30',
        'end_time': '09:15',  # Next day
        'rrc': 'rrc04',
        'malicious_as': ['17488', '9498'],  # Hathway, Bharti Airtel
        'hijacked_prefix': [],  # Google routes
        'label': 'prefix_hijacking',
        'type': 'PH',
        'duration_minutes': 1425  # ~24 hours
    },
    
    'twitter_bitcoin': {
        'name': 'Twitter Bitcoin Phishing Hijack',
        'date': '2018-07-15',
        'start_time': '14:00',
        'end_time': '16:00',
        'rrc': 'rrc04',
        'malicious_as': [],
        'hijacked_prefix': [],
        'label': 'prefix_hijacking',
        'type': 'PH',
        'duration_minutes': 120,
        'impact': 'Twitter traffic redirected to phishing site'
    },
    
    'celer_bridge': {
        'name': 'Celer Bridge Cryptocurrency Hijack',
        'date': '2022-08-17',
        'start_time': '19:39',
        'end_time': '22:07',
        'rrc': 'rrc04',
        'malicious_as': ['14618'],  # QuickhostUK
        'hijacked_prefix': ['44.235.216.0/24'],
        'label': 'prefix_hijacking',
        'type': 'PH',
        'duration_minutes': 148,
        'impact': '$235K cryptocurrency theft'
    },
    
    'cloudflare_111111': {
        'name': 'Cloudflare 1.1.1.1 DNS Hijack',
        'date': '2024-06-27',
        'start_time': '00:00',
        'end_time': '07:37',
        'rrc': 'rrc04',
        'malicious_as': [],
        'hijacked_prefix': ['1.1.1.1/32'],  # More-specific prefix
        'label': 'prefix_hijacking',
        'type': 'PH',
        'duration_minutes': 457,
        'impact': '300 networks in 70 countries affected'
    },

    # ========================================================================
    # PATH MANIPULATION (PM) INCIDENTS
    # ========================================================================
    
    'as47868_prepend': {
        'name': 'AS47868 Excessive Prepending',
        'date': '2009-02-16',
        'start_time': '08:00',
        'end_time': '18:00',
        'rrc': 'rrc00',
        'malicious_as': ['47868'],
        'hijacked_prefix': [],
        'label': 'path_manipulation',
        'type': 'PM',
        'detection_rule': 'as_path_prepend_count',
        'prepend_threshold': 10,
        'duration_minutes': 600
    },
    
    'china_telecom': {
        'name': 'China Telecom Route Leak',
        'date': '2010-04-08',
        'start_time': '07:00',
        'end_time': '07:18',
        'rrc': 'rrc04',
        'malicious_as': ['4134', '4809'],
        'hijacked_prefix': [],
        'label': 'path_manipulation',
        'type': 'PM',
        'duration_minutes': 18,
        'impact': '~15% of global routes'
    },
    
    'verizon_dqe_leak': {
        'name': 'Verizon BGP Optimizer Route Leak (DQE)',
        'date': '2019-06-24',
        'start_time': '10:30',
        'end_time': '12:12',
        'rrc': 'rrc04',
        'malicious_as': ['33154', '701', '394559'],  # DQE, Verizon, Allegheny Tech
        'hijacked_prefix': [],
        'label': 'path_manipulation',
        'type': 'PM',
        'duration_minutes': 102,
        'impact': 'Cloudflare 15% traffic loss, Discord, Reddit, AWS affected'
    },
    
    'china_telecom_safehost': {
        'name': 'SafeHost-China Telecom Route Leak',
        'date': '2019-06-06',
        'start_time': '12:00',
        'end_time': '16:00',
        'rrc': 'rrc04',
        'malicious_as': ['21217', '4134'],  # SafeHost, China Telecom
        'hijacked_prefix': [],
        'label': 'path_manipulation',
        'type': 'PM',
        'duration_minutes': 240,
        'impact': '40,000+ routes, WhatsApp/Microsoft affected'
    },
    
    'china_telecom_canada_korea': {
        'name': 'China Telecom Canada-Korea Route Manipulation',
        'date': '2016-02-15',
        'start_time': '00:00',
        'end_time': '23:59',
        'rrc': 'rrc04',
        'malicious_as': ['4134'],
        'hijacked_prefix': [],
        'label': 'path_manipulation',
        'type': 'PM',
        'duration_minutes': 10080,  # 7 months duration
        'impact': '6-month route hijacking via China'
    },
    
    'china_telecom_italy': {
        'name': 'China Telecom Italian Financial Institution Hijack',
        'date': '2016-11-20',
        'start_time': '15:00',
        'end_time': '00:00',
        'rrc': 'rrc04',
        'malicious_as': ['4134'],
        'hijacked_prefix': [],
        'label': 'path_manipulation',
        'type': 'PM',
        'duration_minutes': 540  # ~9 hours
    },
    
    'china_telecom_scandinavia': {
        'name': 'China Telecom Scandinavia-Japan Route Leak',
        'date': '2017-04-10',
        'start_time': '00:00',
        'end_time': '23:59',
        'rrc': 'rrc04',
        'malicious_as': ['4134'],
        'hijacked_prefix': [],
        'label': 'path_manipulation',
        'type': 'PM',
        'duration_minutes': 50400,  # ~6 weeks
        'impact': 'News organization traffic rerouted'
    },
    
    'brazil_cdn_reroute': {
        'name': 'Brazil CDN Traffic Reroute',
        'date': '2017-10-15',
        'start_time': '18:00',
        'end_time': '18:20',
        'rrc': 'rrc04',
        'malicious_as': [],
        'hijacked_prefix': [],
        'label': 'path_manipulation',
        'type': 'PM',
        'duration_minutes': 20,
        'impact': 'Twitter, Google, major CDNs'
    },

    # ========================================================================
    # DOS/ROUTE LEAK INCIDENTS
    # ========================================================================
    
    'long_aspath': {
        'name': 'Long AS-Path DoS Incident',
        'date': '2009-02-16',
        'start_time': '00:00',
        'end_time': '23:59',
        'rrc': 'rrc04',
        'malicious_as': ['45307'],
        'hijacked_prefix': [],
        'label': 'dos_attack',
        'type': 'DoS',
        'detection_rule': 'as_path_length',
        'path_length_threshold': 100,
        'duration_minutes': 1440
    },
    
    'sql_slammer': {
        'name': 'SQL Slammer Worm BGP Impact',
        'date': '2003-01-25',
        'start_time': '05:30',
        'end_time': '05:40',
        'rrc': 'rrc04',
        'malicious_as': [],
        'hijacked_prefix': [],
        'label': 'dos_attack',
        'type': 'DoS',
        'detection_rule': 'update_burst',
        'duration_minutes': 10,
        'impact': '632K updates/peer'
    },
    
    'as7007': {
        'name': 'AS7007 BGP Incident (Historic)',
        'date': '1997-04-25',
        'start_time': '11:30',
        'end_time': '13:00',
        'rrc': 'rrc00',
        'malicious_as': ['7007'],
        'hijacked_prefix': [],
        'label': 'dos_attack',
        'type': 'DoS',
        'detection_rule': 'route_deaggregation',
        'duration_minutes': 90,
        'impact': 'Global Internet disruption, ~23,000 /24 routes'
    },
    
    'level3_leak': {
        'name': 'Level 3 Route Leak',
        'date': '2017-11-06',
        'start_time': '17:47',
        'end_time': '19:20',
        'rrc': 'rrc04',
        'malicious_as': ['3356'],
        'hijacked_prefix': [],
        'label': 'dos_attack',
        'type': 'DoS',
        'detection_rule': 'route_leak',
        'duration_minutes': 93,
        'impact': 'Comcast, Bell Canada, Netflix, widespread US disruption'
    },
    
    'google_japan': {
        'name': 'Google Japan BGP Leak',
        'date': '2017-08-25',
        'start_time': '03:22',
        'end_time': '03:30',
        'rrc': 'rrc04',
        'malicious_as': ['15169'],
        'hijacked_prefix': [],
        'label': 'dos_attack',
        'type': 'DoS',
        'detection_rule': 'route_leak',
        'duration_minutes': 8,
        'impact': '135,000-160,000 prefixes leaked, KDDI/NTT affected'
    },
    
    'vodafone_india': {
        'name': 'Vodafone India Route Leak',
        'date': '2021-04-17',
        'start_time': '09:00',
        'end_time': '15:00',
        'rrc': 'rrc04',
        'malicious_as': ['55410'],
        'hijacked_prefix': [],
        'label': 'dos_attack',
        'type': 'DoS',
        'detection_rule': 'route_leak',
        'duration_minutes': 360,
        'impact': '30,000+ prefixes, 13× inbound traffic spike'
    },
    
    'taiwan_dns': {
        'name': 'Taiwan DNS Route Hijack',
        'date': '2018-11-12',
        'start_time': '14:00',
        'end_time': '14:03',
        'rrc': 'rrc04',
        'malicious_as': [],
        'hijacked_prefix': [],
        'label': 'dos_attack',
        'type': 'DoS',
        'duration_minutes': 3,
        'impact': 'Public/classified records leaked via Brazil'
    },
    
    'bangladesh_leak': {
        'name': 'Bangladesh Dual BGP Leak',
        'date': '2023-08-28',
        'start_time': '00:00',
        'end_time': '23:59',
        'rrc': 'rrc04',
        'malicious_as': ['58715', '17494'],
        'hijacked_prefix': [],
        'label': 'dos_attack',
        'type': 'DoS',
        'duration_minutes': 1440,
        'impact': '~30,000 routes, global traffic misdirection'
    },

    'code_red_ii': {
        'name': 'Code Red II Worm BGP Impact',
        'date': '2001-07-19',
        'start_time': '08:00',
        'end_time': '22:00',
        'rrc': 'rrc00',
        'malicious_as': [],
        'hijacked_prefix': [],
        'label': 'dos_attack',
        'type': 'DoS',
        'detection_rule': 'update_burst',
        'duration_minutes': 840,
        'impact': 'Global Internet instability'
    },

    'nimda_worm': {
        'name': 'Nimda Worm BGP Impact',
        'date': '2001-09-18',
        'start_time': '08:00',
        'end_time': '20:00',
        'rrc': 'rrc00',
        'malicious_as': [],
        'hijacked_prefix': [],
        'label': 'dos_attack',
        'type': 'DoS',
        'detection_rule': 'update_burst',
        'duration_minutes': 720,
        'impact': '30× BGP update rate increase'
    },

    # ========================================================================
    # ADDITIONAL INCIDENTS (2014-2024)
    # ========================================================================

    # PREFIX HIJACKING - Additional
    'orange_spain_2024': {
        'name': 'Orange Spain RPKI Hijack',
        'date': '2024-01-03',
        'start_time': '14:30',
        'end_time': '18:00',
        'rrc': 'rrc04',
        'malicious_as': ['49581'],
        'hijacked_prefix': [],
        'label': 'prefix_hijacking',
        'type': 'PH',
        'duration_minutes': 210,
        'impact': 'Orange Spain 50% traffic drop via RPKI misconfiguration'
    },

    'bitcanal_hijacks_2018': {
        'name': 'Bitcanal Serial Hijacker',
        'date': '2018-07-10',
        'start_time': '00:00',
        'end_time': '23:59',
        'rrc': 'rrc04',
        'malicious_as': ['197426'],
        'hijacked_prefix': [],
        'label': 'prefix_hijacking',
        'type': 'PH',
        'duration_minutes': 1440,
        'impact': 'Multiple cryptocurrency and payment targets'
    },

    'iran_telegram_2018': {
        'name': 'Iran Telegram BGP Hijack',
        'date': '2018-07-30',
        'start_time': '04:00',
        'end_time': '06:30',
        'rrc': 'rrc04',
        'malicious_as': ['58224', '12880'],
        'hijacked_prefix': ['149.154.160.0/20'],
        'label': 'prefix_hijacking',
        'type': 'PH',
        'duration_minutes': 150,
        'impact': 'Telegram traffic redirected through Iran'
    },

    'turk_telekom_2014': {
        'name': 'Turk Telekom DNS Hijack',
        'date': '2014-03-29',
        'start_time': '00:00',
        'end_time': '12:00',
        'rrc': 'rrc04',
        'malicious_as': ['9121'],
        'hijacked_prefix': ['8.8.8.0/24', '8.8.4.0/24'],
        'label': 'prefix_hijacking',
        'type': 'PH',
        'duration_minutes': 720,
        'impact': 'Google DNS hijacked in Turkey'
    },

    'spamhaus_2013': {
        'name': 'Spamhaus DDoS BGP Amplification',
        'date': '2013-03-18',
        'start_time': '10:00',
        'end_time': '22:00',
        'rrc': 'rrc04',
        'malicious_as': [],
        'hijacked_prefix': [],
        'label': 'prefix_hijacking',
        'type': 'PH',
        'duration_minutes': 720,
        'impact': '300 Gbps DDoS with BGP manipulation'
    },

    # DOS/ROUTE LEAK - Additional
    'facebook_outage_2021': {
        'name': 'Facebook Global Outage',
        'date': '2021-10-04',
        'start_time': '15:39',
        'end_time': '21:00',
        'rrc': 'rrc04',
        'malicious_as': ['32934'],
        'hijacked_prefix': [],
        'label': 'dos_attack',
        'type': 'DoS',
        'detection_rule': 'route_leak',
        'duration_minutes': 321,
        'impact': 'Facebook, Instagram, WhatsApp 6-hour global outage'
    },

    'microsoft_outage_2023': {
        'name': 'Microsoft WAN Routing Issue',
        'date': '2023-01-25',
        'start_time': '07:00',
        'end_time': '12:00',
        'rrc': 'rrc04',
        'malicious_as': ['8075'],
        'hijacked_prefix': [],
        'label': 'dos_attack',
        'type': 'DoS',
        'detection_rule': 'route_leak',
        'duration_minutes': 300,
        'impact': 'Azure, M365, Teams global outage'
    },

    'indosat_2014': {
        'name': 'Indosat Massive Route Leak',
        'date': '2014-04-02',
        'start_time': '18:00',
        'end_time': '22:00',
        'rrc': 'rrc04',
        'malicious_as': ['4761'],
        'hijacked_prefix': [],
        'label': 'dos_attack',
        'type': 'DoS',
        'detection_rule': 'route_leak',
        'duration_minutes': 240,
        'impact': '417,000 prefixes leaked globally'
    },

    'telekom_malaysia_2015': {
        'name': 'Telekom Malaysia Route Leak',
        'date': '2015-06-12',
        'start_time': '08:43',
        'end_time': '10:23',
        'rrc': 'rrc04',
        'malicious_as': ['4788'],
        'hijacked_prefix': [],
        'label': 'dos_attack',
        'type': 'DoS',
        'detection_rule': 'route_leak',
        'duration_minutes': 100,
        'impact': '179,000 prefixes leaked via Level3'
    },

    'aws_route53_leak_2021': {
        'name': 'AWS Route 53 Route Leak',
        'date': '2021-04-16',
        'start_time': '08:00',
        'end_time': '09:30',
        'rrc': 'rrc04',
        'malicious_as': ['16509'],
        'hijacked_prefix': [],
        'label': 'dos_attack',
        'type': 'DoS',
        'detection_rule': 'route_leak',
        'duration_minutes': 90,
        'impact': 'AWS DNS service disruption'
    },

    'centurylink_2018': {
        'name': 'CenturyLink Nationwide Outage',
        'date': '2018-12-27',
        'start_time': '04:00',
        'end_time': '20:00',
        'rrc': 'rrc04',
        'malicious_as': ['209'],
        'hijacked_prefix': [],
        'label': 'dos_attack',
        'type': 'DoS',
        'detection_rule': 'route_leak',
        'duration_minutes': 960,
        'impact': 'US-wide outage, 911 services affected'
    },

    'comcast_hijack_2014': {
        'name': 'Comcast Route Leak',
        'date': '2014-11-07',
        'start_time': '11:00',
        'end_time': '12:30',
        'rrc': 'rrc04',
        'malicious_as': ['7922'],
        'hijacked_prefix': [],
        'label': 'dos_attack',
        'type': 'DoS',
        'detection_rule': 'route_leak',
        'duration_minutes': 90,
        'impact': 'Major US traffic disruption'
    },

    # PATH MANIPULATION - Additional
    'telia_centurylink_2019': {
        'name': 'Telia-CenturyLink Route Leak',
        'date': '2019-06-06',
        'start_time': '10:00',
        'end_time': '12:00',
        'rrc': 'rrc04',
        'malicious_as': ['1299', '3356'],
        'hijacked_prefix': [],
        'label': 'path_manipulation',
        'type': 'PM',
        'duration_minutes': 120,
        'impact': 'Cloudflare, Discord, Reddit major disruption'
    },

    'sk_broadband_2016': {
        'name': 'SK Broadband Routing Incident',
        'date': '2016-11-03',
        'start_time': '02:00',
        'end_time': '08:00',
        'rrc': 'rrc04',
        'malicious_as': ['9318'],
        'hijacked_prefix': [],
        'label': 'path_manipulation',
        'type': 'PM',
        'duration_minutes': 360,
        'impact': 'South Korea internet disruption'
    },

    'cogent_sprint_2008': {
        'name': 'Cogent-Sprint Depeering',
        'date': '2008-10-30',
        'start_time': '00:00',
        'end_time': '23:59',
        'rrc': 'rrc04',
        'malicious_as': ['174', '1239'],
        'hijacked_prefix': [],
        'label': 'path_manipulation',
        'type': 'PM',
        'duration_minutes': 1440,
        'impact': 'Major tier-1 partition event'
    },

    'ntt_leak_2020': {
        'name': 'NTT Communications Route Leak',
        'date': '2020-06-16',
        'start_time': '05:00',
        'end_time': '07:00',
        'rrc': 'rrc04',
        'malicious_as': ['2914'],
        'hijacked_prefix': [],
        'label': 'path_manipulation',
        'type': 'PM',
        'duration_minutes': 120,
        'impact': 'T-Mobile, Cloudflare service issues'
    },

    'qrator_2017': {
        'name': 'Qrator Labs Detection - Route Hijack',
        'date': '2017-08-29',
        'start_time': '03:00',
        'end_time': '05:00',
        'rrc': 'rrc04',
        'malicious_as': ['58879'],
        'hijacked_prefix': [],
        'label': 'path_manipulation',
        'type': 'PM',
        'duration_minutes': 120,
        'impact': 'Traffic interception via AS path manipulation'
    },
}


# ============================================================================
# CONFIGURATION
# ============================================================================

BASE_RIPE_URL = "https://data.ris.ripe.net"
RIPE_DIR = "/home/smotaali/BGP_Traffic_Generation/RIPE/RIPE_INCIDENTS"
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
    origin_as = record.get('Origin_AS', '') or (as_list[-1] if as_list else '')
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

        # Deaggregation: very specific more‑specifics (e.g., many /24s)
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
        print(f"  ✓ Downloaded: {os.path.basename(local_path)}")
        return True
    except Exception as e:
        print(f"  ✗ Error downloading {url}: {e}")
        return False


def decompress_gz(gz_file, output_file):
    """Decompress gzip file."""
    try:
        with gzip.open(gz_file, 'rb') as f_in:
            with open(output_file, 'wb') as f_out:
                shutil.copyfileobj(f_in, f_out)
        return True
    except Exception as e:
        print(f"  ✗ Error decompressing {gz_file}: {e}")
        return False


def parse_bgpdump_line(line):
    """Parse a single line from bgpdump -m output."""
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
                'Origin_AS': '',
                'Next_Hop': '',
                'Local_Pref': '',
                'MED': '',
                'Community': '',
                'Atomic_Aggregate': '',
                'Aggregator': ''
            }
        
        as_path = parts[6] if len(parts) > 6 else ''
        origin = parts[7] if len(parts) > 7 else ''
        next_hop = parts[8] if len(parts) > 8 else ''
        local_pref = parts[9] if len(parts) > 9 else ''
        med = parts[10] if len(parts) > 10 else ''
        community = parts[11] if len(parts) > 11 else ''
        atomic_agg = parts[12] if len(parts) > 12 else ''
        aggregator = parts[13] if len(parts) > 13 else ''
        
        origin_as = ''
        if as_path:
            as_list = as_path.strip().split()
            if as_list:
                origin_as = as_list[-1]
        
        return {
            'MRT_Type': 'BGP4MP',
            'Time': date_time,
            'Entry_Type': 'A',
            'Peer_IP': peer_ip,
            'Peer_AS': peer_as,
            'Prefix': prefix,
            'AS_Path': as_path,
            'Origin_AS': origin_as,
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
        print("  ✗ bgpdump not found. Install with: apt-get install bgpdump")
        return []
    except subprocess.TimeoutExpired:
        print("  ✗ bgpdump timeout")
        return []
    except Exception as e:
        print(f"  ✗ Error parsing MRT file: {e}")
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
            print(f"✓ {len(records)} records")
            all_records.extend(records)
        else:
            print("✓ 0 records")
        
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
                     'Prefix', 'AS_Path', 'Origin_AS', 'Next_Hop', 'Local_Pref',
                     'MED', 'Community', 'Atomic_Aggregate', 'Aggregator', 
                     'Label', 'Confidence', 'Incident']
        
        try:
            with open(csv_output, 'w', newline='', encoding='utf-8') as csvfile:
                writer = csv.DictWriter(csvfile, fieldnames=fieldnames, restval='')
                writer.writeheader()
                writer.writerows(labeled_records)
            
            print(f"✓ CSV created: {csv_output}")
            print(f"✓ Total records: {len(labeled_records):,}")
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
                print(f"  Confidence: {anomaly_sample['Confidence']}")
        
        except Exception as e:
            print(f"✗ Error writing CSV: {e}")
            import traceback
            traceback.print_exc()
    else:
        print("✗ No records to write")
    
    return len(labeled_records), anomaly_counts


def main():
    """Main execution function."""
    print("=" * 80)
    print("BGP Incident Data Collector and Labeler")
    print("Comprehensive Real-World BGP Anomaly Detection Dataset Generator")
    print("=" * 80)
    
    create_directories()
    
    # Print available incidents
    print(f"\nAvailable incidents: {len(INCIDENTS)}")
    ph_count = sum(1 for c in INCIDENTS.values() if c['type'] == 'PH')
    pm_count = sum(1 for c in INCIDENTS.values() if c['type'] == 'PM')
    dos_count = sum(1 for c in INCIDENTS.values() if c['type'] == 'DoS')
    print(f"  Prefix Hijacking (PH): {ph_count}")
    print(f"  Path Manipulation (PM): {pm_count}")
    print(f"  DoS/Route Leak (DoS): {dos_count}")
    
    print("\nProcessing all incidents...")
    
    # Process each incident
    total_records = 0
    total_anomalies = 0
    summary = []
    
    for incident_key, incident_config in INCIDENTS.items():
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
            print(f"\n✗ Error processing {incident_key}: {e}")
            import traceback
            traceback.print_exc()
    
    # Print final summary
    print("\n" + "=" * 80)
    print("FINAL SUMMARY")
    print("=" * 80)
    print(f"\nTotal records collected: {total_records:,}")
    print(f"Total anomalies labeled: {total_anomalies:,}")
    print(f"Anomaly rate: {(total_anomalies/total_records*100):.2f}%" if total_records > 0 else "N/A")
    
    print("\nBy Anomaly Type:")
    ph_total = sum(item['anomalies'] for item in summary if 'Hijack' in item['incident'] or 'hijack' in item['incident'].lower())
    pm_total = sum(item['anomalies'] for item in summary if 'Prepend' in item['incident'] or 'Manipulation' in item['incident'] or 'Leak' in item['incident'] and 'route' in item['incident'].lower())
    dos_total = total_anomalies - ph_total - pm_total
    
    print(f"  Prefix Hijacking: {ph_total:,}")
    print(f"  Path Manipulation: {pm_total:,}")
    print(f"  DoS/Route Leak: {dos_total:,}")
    
    print(f"\nAll data saved in: {os.path.abspath(RIPE_DIR)}")
    
    # Cleanup temp directory
    try:
        shutil.rmtree(TEMP_DIR)
        print("✓ Temporary files cleaned up")
    except Exception as e:
        print(f"Warning: {e}")


if __name__ == "__main__":
    main()
