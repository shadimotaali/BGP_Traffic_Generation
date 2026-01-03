#!/usr/bin/env python3
"""
BGP Incident Reference Database

This module provides known BGP incidents that can be used to:
1. Cross-reference discovered anomalies with real-world events
2. Validate labeling by checking if detected anomalies match known incidents
3. Provide ground truth for specific time periods

Sources of BGP incident information:
- BGPStream (https://bgpstream.com/)
- RIPE RIS (https://www.ripe.net/analyse/internet-measurements/routing-information-service-ris)
- CAIDA BGP Hijacks (https://bgp.caida.org/hijacks)
- Cloudflare Radar (https://radar.cloudflare.com/)

Author: BGP Traffic Generation Project
"""

from datetime import datetime, timedelta
from typing import List, Dict, Optional
import pandas as pd


# Known major BGP incidents (can be extended)
# Format: {start_time, end_time, type, description, affected_prefixes, source}
KNOWN_BGP_INCIDENTS = [
    {
        "id": "pakistan_youtube_2008",
        "start": datetime(2008, 2, 24, 18, 47),
        "end": datetime(2008, 2, 24, 20, 7),
        "type": "prefix_hijacking",
        "description": "Pakistan Telecom hijacked YouTube prefixes",
        "affected_prefixes": ["208.65.152.0/22", "208.65.153.0/24"],
        "affected_asns": [17557, 36561],
        "source": "historical"
    },
    {
        "id": "china_telecom_2010",
        "start": datetime(2010, 4, 8, 15, 0),
        "end": datetime(2010, 4, 8, 15, 18),
        "type": "route_leak",
        "description": "China Telecom leaked 37,000 prefixes",
        "affected_prefixes": [],  # Too many to list
        "affected_asns": [4134],
        "source": "historical"
    },
    {
        "id": "google_leak_2017",
        "start": datetime(2017, 8, 25, 3, 22),
        "end": datetime(2017, 8, 25, 4, 35),
        "type": "route_leak",
        "description": "Google accidentally leaked internal routes via AS15169",
        "affected_prefixes": [],
        "affected_asns": [15169],
        "source": "historical"
    },
    {
        "id": "rostelecom_2020",
        "start": datetime(2020, 4, 1, 19, 28),
        "end": datetime(2020, 4, 1, 19, 55),
        "type": "prefix_hijacking",
        "description": "Rostelecom hijacked traffic from Cloudflare, Akamai, and others",
        "affected_prefixes": [],
        "affected_asns": [12389],
        "source": "historical"
    },
    {
        "id": "facebook_outage_2021",
        "start": datetime(2021, 10, 4, 15, 39),
        "end": datetime(2021, 10, 4, 21, 0),
        "type": "route_withdrawal",
        "description": "Facebook withdrew all BGP routes causing global outage",
        "affected_prefixes": ["157.240.0.0/16", "129.134.0.0/16"],
        "affected_asns": [32934],
        "source": "historical"
    },
]


class BGPIncidentDatabase:
    """
    Database of known BGP incidents for cross-referencing.
    """

    def __init__(self):
        self.incidents = KNOWN_BGP_INCIDENTS.copy()

    def add_incident(self, incident: dict):
        """Add a custom incident to the database."""
        required_fields = ['id', 'start', 'end', 'type', 'description']
        for field in required_fields:
            if field not in incident:
                raise ValueError(f"Missing required field: {field}")
        self.incidents.append(incident)

    def find_incidents_in_timerange(self,
                                     start: datetime,
                                     end: datetime) -> List[dict]:
        """
        Find known incidents that overlap with the given time range.

        Args:
            start: Start of time range
            end: End of time range

        Returns:
            List of matching incidents
        """
        matches = []
        for incident in self.incidents:
            # Check for overlap
            if incident['start'] <= end and incident['end'] >= start:
                matches.append(incident)
        return matches

    def find_incidents_by_asn(self, asn: int) -> List[dict]:
        """Find incidents involving a specific ASN."""
        matches = []
        for incident in self.incidents:
            if 'affected_asns' in incident and asn in incident['affected_asns']:
                matches.append(incident)
        return matches

    def find_incidents_by_type(self, incident_type: str) -> List[dict]:
        """Find incidents of a specific type."""
        return [i for i in self.incidents if i['type'] == incident_type]

    def get_all_incidents(self) -> List[dict]:
        """Return all known incidents."""
        return self.incidents.copy()


def cross_reference_with_incidents(df: pd.DataFrame,
                                    time_col: str = 'window_start',
                                    asn_col: str = None) -> pd.DataFrame:
    """
    Cross-reference DataFrame with known BGP incidents.

    Args:
        df: DataFrame with anomaly detection results
        time_col: Column containing timestamps
        asn_col: Optional column containing ASN data

    Returns:
        DataFrame with incident cross-reference columns added
    """
    db = BGPIncidentDatabase()

    df = df.copy()
    df['known_incident_id'] = None
    df['known_incident_type'] = None
    df['known_incident_desc'] = None

    if time_col not in df.columns:
        print(f"[!] Time column '{time_col}' not found")
        return df

    # Parse timestamps
    df['_temp_time'] = pd.to_datetime(df[time_col], errors='coerce')

    # Check each row against known incidents
    matched_count = 0
    for idx, row in df.iterrows():
        if pd.isna(row['_temp_time']):
            continue

        row_time = row['_temp_time'].to_pydatetime()

        # Find incidents at this time
        matching = db.find_incidents_in_timerange(
            row_time - timedelta(minutes=5),
            row_time + timedelta(minutes=5)
        )

        if matching:
            incident = matching[0]  # Take first match
            df.at[idx, 'known_incident_id'] = incident['id']
            df.at[idx, 'known_incident_type'] = incident['type']
            df.at[idx, 'known_incident_desc'] = incident['description']
            matched_count += 1

    df.drop(columns=['_temp_time'], inplace=True)

    print(f"[+] Cross-referenced with known incidents: {matched_count} matches found")

    return df


def generate_labeling_suggestions(df: pd.DataFrame,
                                   anomaly_label_col: str = 'discovered_label') -> dict:
    """
    Generate labeling suggestions based on analysis results.

    This helps you decide how to label your RIPE data.
    """
    suggestions = {
        'high_confidence_normal': [],
        'high_confidence_attack': [],
        'needs_manual_review': [],
        'labeling_strategy': ''
    }

    if anomaly_label_col not in df.columns:
        return suggestions

    # Analyze the distribution
    label_dist = df[anomaly_label_col].value_counts(normalize=True)

    likely_normal_rate = label_dist.get('likely_normal', 0)
    anomaly_rate = label_dist.get('high_confidence_anomaly', 0) + label_dist.get('likely_anomaly', 0)
    uncertain_rate = label_dist.get('uncertain', 0)

    # Generate strategy based on distribution
    if likely_normal_rate > 0.8:
        suggestions['labeling_strategy'] = """
        STRATEGY: Conservative Normal Labeling

        Your data appears to be predominantly normal traffic (>{:.0%}).

        Recommended approach:
        1. Label 'likely_normal' samples as 'normal'
        2. Label 'high_confidence_anomaly' samples as 'anomaly' (potential attacks)
        3. MANUALLY REVIEW 'likely_anomaly' and 'uncertain' samples
        4. Cross-reference anomalies with known BGP incidents for context

        This is a SAFE approach when you're not sure about the data.
        """.format(likely_normal_rate)

    elif anomaly_rate > 0.3:
        suggestions['labeling_strategy'] = """
        STRATEGY: Mixed/Suspicious Data

        Your data contains a significant anomaly rate ({:.0%}).
        This could indicate:
        - Data collected during a known incident
        - Collector issues or misconfiguration
        - Legitimate attack traffic

        Recommended approach:
        1. DO NOT assume this is "normal" training data
        2. Cross-reference timestamps with known BGP incidents
        3. Check the RIPE collector status for that time period
        4. Consider using only 'likely_normal' samples for baseline
        5. Investigate 'high_confidence_anomaly' samples individually
        """.format(anomaly_rate)

    else:
        suggestions['labeling_strategy'] = """
        STRATEGY: Standard Labeling with Review

        Your data has a typical distribution with some anomalies.

        Recommended approach:
        1. Label 'likely_normal' samples as 'normal'
        2. Keep 'uncertain' samples unlabeled or for validation
        3. Use 'high_confidence_anomaly' as attack examples (with verification)
        4. Document your labeling decisions for reproducibility
        """

    return suggestions


# Utility to print incident information
def print_known_incidents():
    """Print all known BGP incidents in the database."""
    db = BGPIncidentDatabase()

    print("\n" + "=" * 80)
    print("KNOWN BGP INCIDENTS DATABASE")
    print("=" * 80)

    for incident in db.get_all_incidents():
        print(f"\n📅 [{incident['id']}]")
        print(f"   Type: {incident['type']}")
        print(f"   Time: {incident['start']} to {incident['end']}")
        print(f"   Description: {incident['description']}")
        if incident.get('affected_asns'):
            print(f"   Affected ASNs: {incident['affected_asns']}")

    print("\n" + "=" * 80)


if __name__ == "__main__":
    print_known_incidents()

    print("\nTo add custom incidents, use the BGPIncidentDatabase class:")
    print("""
    from bgp_incident_reference import BGPIncidentDatabase

    db = BGPIncidentDatabase()
    db.add_incident({
        'id': 'my_incident_2025',
        'start': datetime(2025, 11, 16, 10, 0),
        'end': datetime(2025, 11, 16, 12, 0),
        'type': 'prefix_hijacking',
        'description': 'Custom incident for my dataset',
        'affected_asns': [12345]
    })
    """)
