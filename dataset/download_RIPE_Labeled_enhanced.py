#!/usr/bin/env python3
"""
Script to collect RIPE RRC04 update packets for a specified time period
and convert them to CSV format using bgpdump with proper parsing.
"""

import os
import gzip
import shutil
import subprocess
import csv
from datetime import datetime, timedelta
from urllib.request import urlopen
from pathlib import Path

# Configuration
BASE_URL = "https://data.ris.ripe.net/rrc04/2025.11"
RIPE_DIR = "./RIPE"
OUTPUT_DIR = os.path.join(RIPE_DIR, "mrt_files")
CSV_OUTPUT = os.path.join(RIPE_DIR, "rrc04_20251117_updates.csv")
TEMP_DIR = os.path.join(RIPE_DIR, "temp_mrt")

# Time range - November 16, 2025 00:05 to November 17, 2025 00:00
START_FILE = "updates.20251117.0005.gz"
END_FILE = "updates.20251118.0000.gz"

def create_directories():
    """Create necessary directories."""
    Path(OUTPUT_DIR).mkdir(parents=True, exist_ok=True)
    Path(TEMP_DIR).mkdir(parents=True, exist_ok=True)

def download_file(url, local_path):
    """Download a file from URL."""
    try:
        print(f"Downloading {url}...")
        with urlopen(url) as response:
            with open(local_path, 'wb') as out_file:
                out_file.write(response.read())
        print(f"✓ Downloaded: {local_path}")
        return True
    except Exception as e:
        print(f"✗ Error downloading {url}: {e}")
        return False

def decompress_gz(gz_file, output_file):
    """Decompress gzip file."""
    try:
        with gzip.open(gz_file, 'rb') as f_in:
            with open(output_file, 'wb') as f_out:
                shutil.copyfileobj(f_in, f_out)
        return True
    except Exception as e:
        print(f"✗ Error decompressing {gz_file}: {e}")
        return False

def parse_bgpdump_line(line):
    """
    Parse a single line from bgpdump -m output.

    Format for announcements:
    BGP4MP|timestamp|A|peer_ip|peer_as|prefix|as_path|ORIGIN|next_hop|local_pref|med|community|atomic_agg|aggregator

    Format for withdrawals:
    BGP4MP|timestamp|W|peer_ip|peer_as|prefix

    Returns a record dictionary or None if line is invalid.
    """
    line = line.strip()
    if not line:
        return None

    parts = line.split('|')

    # Minimum fields required
    if len(parts) < 6:
        return None

    try:
        msg_type = parts[0]  # Should be 'BGP4MP'
        if msg_type != 'BGP4MP':
            return None

        timestamp = int(parts[1])
        dt = datetime.utcfromtimestamp(timestamp)
        date_time = dt.strftime('%Y-%m-%d %H:%M:%S')

        update_type = parts[2]  # 'A' for Announce, 'W' for Withdraw
        peer_ip = parts[3]
        peer_as = parts[4]
        prefix = parts[5]

        # For withdrawals, we only have these fields
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
                'Aggregator': '',
                'Label': 'normal'
            }

        # For announcements, parse additional fields
        as_path = parts[6] if len(parts) > 6 else ''
        origin = parts[7] if len(parts) > 7 else ''
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
            'Origin': origin,
            'Next_Hop': next_hop,
            'Local_Pref': local_pref,
            'MED': med,
            'Community': community,
            'Atomic_Aggregate': atomic_agg,
            'Aggregator': aggregator,
            'Label': 'normal'
        }

    except (ValueError, IndexError) as e:
        return None

def parse_mrt_file_with_bgpdump(mrt_file, debug=False):
    """
    Parse MRT file using bgpdump and extract all BGP attributes.
    """
    records = []

    try:
        # Run bgpdump with -m flag for machine-readable output
        result = subprocess.run(
            ['bgpdump', '-m', mrt_file],
            capture_output=True,
            text=True,
            check=False
        )

        if result.returncode != 0:
            if debug:
                print(f"    [DEBUG] bgpdump error: {result.stderr}")
            return []

        # Parse each line
        lines = result.stdout.strip().split('\n')

        for line in lines:
            record = parse_bgpdump_line(line)
            if record:
                records.append(record)

        if debug and records:
            print(f"    [DEBUG] Parsed {len(records)} records from {len(lines)} lines")
            print(f"    [DEBUG] Sample record: {records[0]}")

    except FileNotFoundError:
        print("✗ bgpdump not found. Install with: apt-get install bgpdump")
        return []
    except Exception as e:
        if debug:
            print(f"✗ Error parsing MRT file: {e}")
        return []

    return records

def collect_and_process_updates():
    """Main function to collect and process update packets."""
    print("=" * 70)
    print("RIPE RRC04 Update Packet Collector (with bgpdump)")
    print("=" * 70)

    create_directories()

    # Generate list of files to download (every 5 minutes)
    files_to_download = []

    # Parse start and end times
    start_time = datetime.strptime("20251117.0005", "%Y%m%d.%H%M")
    end_time = datetime.strptime("20251118.0000", "%Y%m%d.%H%M")

    current_time = start_time
    while current_time <= end_time:
        filename = f"updates.{current_time.strftime('%Y%m%d.%H%M')}.gz"
        files_to_download.append(filename)
        current_time += timedelta(minutes=5)

    print(f"\nTotal files to download: {len(files_to_download)}")
    print(f"Time range: {start_time} to {end_time}")
    print()

    # Download files
    downloaded_files = []
    for i, filename in enumerate(files_to_download, 1):
        url = f"{BASE_URL}/{filename}"
        local_path = os.path.join(OUTPUT_DIR, filename)

        # Skip if already downloaded
        if os.path.exists(local_path):
            print(f"[{i}/{len(files_to_download)}] Already exists: {filename}")
            downloaded_files.append(local_path)
            continue

        print(f"[{i}/{len(files_to_download)}] ", end="")
        if download_file(url, local_path):
            downloaded_files.append(local_path)
        else:
            print(f"  (Skipping {filename})")

    print(f"\nTotal files available: {len(downloaded_files)}")

    # Decompress and convert
    print("\n" + "=" * 70)
    print("Decompressing and parsing MRT files...")
    print("=" * 70)

    all_records = []

    for i, gz_file in enumerate(downloaded_files, 1):
        mrt_file = os.path.join(TEMP_DIR, os.path.basename(gz_file).replace('.gz', ''))

        print(f"[{i}/{len(downloaded_files)}] Processing {os.path.basename(gz_file)}...", end=" ")

        # Decompress
        if not decompress_gz(gz_file, mrt_file):
            print("Failed")
            continue

        # Parse with bgpdump (enable debug for first file)
        records = parse_mrt_file_with_bgpdump(mrt_file, debug=(i == 1))

        if records:
            print(f"✓ {len(records)} records")
            all_records.extend(records)
        else:
            print(f"✓ 0 records")

        # Clean up temp file
        try:
            os.remove(mrt_file)
        except:
            pass

    # Write final CSV
    print("\n" + "=" * 70)
    print(f"Writing final CSV: {CSV_OUTPUT}")
    print("=" * 70)

    if all_records:
        fieldnames = ['MRT_Type', 'Time', 'Entry_Type', 'Peer_IP', 'Peer_AS',
                     'Prefix', 'AS_Path', 'Origin', 'Next_Hop', 'Local_Pref',
                     'MED', 'Community', 'Atomic_Aggregate', 'Aggregator', 'Label']
        try:
            with open(CSV_OUTPUT, 'w', newline='', encoding='utf-8') as csvfile:
                writer = csv.DictWriter(csvfile, fieldnames=fieldnames, restval='')
                writer.writeheader()
                writer.writerows(all_records)

            print(f"✓ CSV file created: {CSV_OUTPUT}")
            print(f"✓ Total records: {len(all_records):,}")

            # Show statistics
            announcements = sum(1 for r in all_records if r['Entry_Type'] == 'A')
            withdrawals = sum(1 for r in all_records if r['Entry_Type'] == 'W')
            with_med = sum(1 for r in all_records if r.get('MED'))
            with_community = sum(1 for r in all_records if r.get('Community'))

            print(f"\nStatistics:")
            print(f"  Announcements: {announcements:,}")
            print(f"  Withdrawals: {withdrawals:,}")
            print(f"  Records with Origin AS: {with_origin:,}")
            print(f"  Records with MED: {with_med:,}")
            print(f"  Records with Communities: {with_community:,}")

            # Show sample records
            if announcements > 0:
                print(f"\nSample announcement:")
                sample_a = next((r for r in all_records if r['Entry_Type'] == 'A'), None)
                if sample_a:
                    for key, value in sample_a.items():
                        if value:
                            print(f"  {key}: {value}")

            # Verify file was written
            if os.path.exists(CSV_OUTPUT):
                file_size = os.path.getsize(CSV_OUTPUT)
                print(f"\n✓ File size: {file_size:,} bytes")
            else:
                print("✗ Error: CSV file was not created")
        except Exception as e:
            print(f"✗ Error writing CSV: {e}")
            import traceback
            traceback.print_exc()
    else:
        print("✗ No records generated")
        print("\nPossible issues:")
        print("  - bgpdump not installed (install with: apt-get install bgpdump)")
        print("  - MRT files are empty or corrupted")
        print("  - No BGP UPDATE messages in the time range")

    # Cleanup - only remove temp files, keep MRT files and CSV
    print("\nCleaning up temporary files...")
    try:
        shutil.rmtree(TEMP_DIR)
        print("✓ Temporary files cleaned up")
        print(f"\n" + "=" * 70)
        print(f"Summary:")
        print(f"=" * 70)
        print(f"MRT files saved in: {OUTPUT_DIR}")
        print(f"CSV file saved in: {CSV_OUTPUT}")
        print(f"All files located in: {os.path.abspath(RIPE_DIR)}")
    except Exception as e:
        print(f"Warning: {e}")

if __name__ == "__main__":
    collect_and_process_updates()
