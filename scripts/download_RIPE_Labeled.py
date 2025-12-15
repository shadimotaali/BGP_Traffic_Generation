#!/usr/bin/env python3
"""
Script to collect RIPE RRC04 update packets for a specified time period
and convert them to CSV format using bgpdump.
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
CSV_OUTPUT = os.path.join(RIPE_DIR, "rrc04_updates.csv")
TEMP_DIR = os.path.join(RIPE_DIR, "temp_mrt")

# Time range - November 17, 2025 05:00 to November 18, 2025 00:00
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
        print(f"✓ Decompressed: {gz_file}")
        return True
    except Exception as e:
        print(f"✗ Error decompressing {gz_file}: {e}")
        return False

def mrt_to_csv(mrt_file, csv_file):
    """Convert MRT file to CSV using bgpdump."""
    try:
        # bgpdump outputs in a specific format, we'll parse it
        result = subprocess.run(
            ['bgpdump', '-m', mrt_file],
            capture_output=True,
            text=True,
            check=False
        )
        
        if result.returncode != 0:
            print(f"✗ bgpdump error: {result.stderr}")
            return False
        
        # Write the raw output to CSV
        with open(csv_file, 'w') as f:
            f.write(result.stdout)
        return True
    except FileNotFoundError:
        print("✗ bgpdump not found. Please install it: apt-get install bgptools")
        return False
    except Exception as e:
        print(f"✗ Error converting MRT to CSV: {e}")
        return False

def parse_bgpdump_output(bgpdump_lines):
    """
    Parse bgpdump -m output and convert to structured data.
    bgpdump -m actual format for BGP4MP:
    BGP4MP|TIMESTAMP|TYPE|PEER_IP|PEER_AS|PREFIX|AS_PATH|[ORIGIN|NEXTHOP|LOCALPREF|MED|COMMUNITIES|...]
    
    Example with A (Announce):
    BGP4MP|1763424000|A|192.65.185.3|513|193.105.156.0/24|513 29222 29222 1299 3216 8369|INCOMPLETE|192.65.185.1|...
    
    Example with W (Withdraw):
    BGP4MP|1763424000|W|192.65.185.140|29222|130.137.124.0/24
    """
    records = []
    for line in bgpdump_lines:
        line = line.strip()
        if not line:
            continue
        
        parts = line.split('|')
        
        # BGP4MP format check
        if len(parts) < 6:
            continue
        
        try:
            # BGP4MP format: BGP4MP|TIMESTAMP|TYPE|PEER_IP|PEER_AS|PREFIX|...
            msg_type = parts[0]  # Should be 'BGP4MP'
            timestamp = int(parts[1])
            update_type = parts[2]  # 'A' for Announce, 'W' for Withdraw
            peer_ip = parts[3]
            peer_as = parts[4]
            prefix = parts[5] if len(parts) > 5 else ""
            as_path = parts[6] if len(parts) > 6 else ""
            origin = parts[7] if len(parts) > 7 else ""
            next_hop = parts[8] if len(parts) > 8 else ""
            local_pref = parts[9] if len(parts) > 9 else ""
            med = parts[10] if len(parts) > 10 else ""
            communities = parts[11] if len(parts) > 11 else ""
            atomic_agg = parts[12] if len(parts) > 12 else ""
            aggregator = parts[13] if len(parts) > 13 else ""
            
            # Convert Unix timestamp to readable datetime
            dt = datetime.utcfromtimestamp(timestamp)
            date_time = dt.strftime('%Y-%m-%d %H:%M:%S')
            
            record = {
                'MRT_Type': msg_type,
                'Time': date_time,
                'Entry_Type': update_type,
                'Peer_IP': peer_ip,
                'Peer_AS': peer_as,
                'Prefix': prefix,
                'AS_Path': as_path,
                'Origin_AS': origin,
                'Next_Hop': next_hop,
                'Local_Pref': local_pref,
                'MED': med,
                'Community': communities,
                'Atomic_Aggregate': atomic_agg,
                'Aggregator': aggregator,
                'Label': 'normal'
            }
            records.append(record)
                
        except (ValueError, IndexError) as e:
            # Silently skip malformed lines
            continue
    
    return records

def collect_and_process_updates():
    """Main function to collect and process update packets."""
    print("=" * 70)
    print("RIPE RRC04 Update Packet Collector")
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
        
        print(f"[{i}/{len(files_to_download)}] ", end="")
        if download_file(url, local_path):
            downloaded_files.append(local_path)
        else:
            print(f"  (Skipping {filename})")
    
    print(f"\nSuccessfully downloaded {len(downloaded_files)} files")
    
    # Decompress and convert
    print("\n" + "=" * 70)
    print("Decompressing and converting files...")
    print("=" * 70)
    
    all_records = []
    
    for i, gz_file in enumerate(downloaded_files, 1):
        mrt_file = os.path.join(TEMP_DIR, os.path.basename(gz_file).replace('.gz', ''))
        
        print(f"[{i}/{len(downloaded_files)}] Processing {os.path.basename(gz_file)}...", end=" ")
        
        # Decompress
        if not decompress_gz(gz_file, mrt_file):
            print("Skipped")
            continue
        
        # Convert with bgpdump
        csv_temp = mrt_file + ".txt"
        if mrt_to_csv(mrt_file, csv_temp):
            # Parse output
            with open(csv_temp, 'r') as f:
                bgpdump_lines = f.readlines()
            
            # Debug: show first few lines if empty
            if bgpdump_lines:
                # Show first 3 lines for debugging
                print(f"\n[DEBUG] First lines from bgpdump:")
                for idx, line in enumerate(bgpdump_lines[:3]):
                    print(f"  Line {idx}: {line[:100]}")
                
                records = parse_bgpdump_output(bgpdump_lines)
                print(f"  Parsed {len(records)} records from {len(bgpdump_lines)} lines")
                if records:
                    print(f"  Sample record: {records[0]}")
                all_records.extend(records)
                print(f"✓ Total accumulated: {len(all_records)} records\n")
            else:
                print(f"✓ (empty file)")
        
        # Clean up temp files
        try:
            os.remove(mrt_file)
            os.remove(csv_temp)
        except:
            pass
    
    # Write final CSV
    print("\n" + "=" * 70)
    print(f"Writing final CSV: {CSV_OUTPUT}")
    print("=" * 70)
    
    if all_records:
        fieldnames = ['MRT_Type', 'Time', 'Entry_Type', 'Peer_IP', 'Peer_AS', 
                     'Prefix', 'AS_Path', 'Origin_AS', 'Next_Hop', 'Local_Pref', 
                     'MED', 'Community', 'Atomic_Aggregate', 'Aggregator', 'Label']
        
        try:
            with open(CSV_OUTPUT, 'w', newline='', encoding='utf-8') as csvfile:
                writer = csv.DictWriter(csvfile, fieldnames=fieldnames, restval='')
                writer.writeheader()
                writer.writerows(all_records)
            
            print(f"✓ CSV file created: {CSV_OUTPUT}")
            print(f"✓ Total records: {len(all_records)}")
            print(f"\nColumns: {', '.join(fieldnames)}")
            
            # Verify file was written
            if os.path.exists(CSV_OUTPUT):
                file_size = os.path.getsize(CSV_OUTPUT)
                print(f"✓ File size: {file_size} bytes")
            else:
                print("✗ Error: CSV file was not created")
        except Exception as e:
            print(f"✗ Error writing CSV: {e}")
            print(f"✗ Records count: {len(all_records)}")
            if all_records:
                print(f"✗ Sample record keys: {list(all_records[0].keys())}")
    else:
        print("✗ No records generated")
    
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