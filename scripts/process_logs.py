#!/usr/bin/env python3
"""
Logcat Post-Processing Script for Emergency Data Collector

Usage:
    python process_logs.py [folder_path]
    
Default folder: ./
"""

import os
import sys
import re
from collections import defaultdict
from datetime import datetime
import subprocess

def parse_logcat_timestamp(line):
    """
    Parse Android logcat timestamp from a line.
    Format: "MM-DD HH:MM:SS.mmm" (e.g., "02-04 16:44:17.123")
    Returns datetime object or None if no timestamp found.
    """
    # Match logcat timestamp format at start of line
    match = re.match(r'^(\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}\.\d{3})', line)
    if match:
        timestamp_str = match.group(1)
        try:
            # Parse with current year (logcat doesn't include year)
            current_year = datetime.now().year
            dt = datetime.strptime(f"{current_year}-{timestamp_str}", "%Y-%m-%d %H:%M:%S.%f")
            return dt
        except ValueError:
            return None
    return None

def extract_base_name(filename):
    """
    Extract base name (timestamp identifier) from filename.
    Example: 
        US_T-Mobile_Pixel_9_2e7b6568558a706f_20260204_1_1_164417_n42.710147_w84.458661_radio.txt
        -> US_T-Mobile_Pixel_9_2e7b6568558a706f_20260204_1_1_164417_n42.710147_w84.458661
    """
    # Remove extension
    name_without_ext = filename.rsplit('.txt', 1)[0]
    
    # Remove buffer suffix (_radio, _main, _events, _system, _crash, _kernel)
    suffixes = ['_radio', '_main', '_events', '_system', '_crash', '_kernel']
    for suffix in suffixes:
        if name_without_ext.endswith(suffix):
            return name_without_ext[:-len(suffix)]
    
    return name_without_ext

def extract_scenario_number(base_name):
    """
    Extract scenario number from base name.
    Format: {country}_{operator}_{model}_{deviceId}_{date}_{scenario}_{experiment}_{time}_{location}
    Example: US_T-Mobile_Pixel_9_2e7b6568558a706f_20260204_1_1_164417_n42.710147_w84.458661
                                                                      ^ scenario number
    """
    parts = base_name.split('_')
    # Scenario number is typically at index -5 (before experiment number, time, location)
    # Format: ..._date_scenario_experiment_time_location
    try:
        # Find the date part (8 digits starting with 20)
        for i, part in enumerate(parts):
            if len(part) == 8 and part.startswith('20'):
                # Scenario is next part after date
                if i + 1 < len(parts):
                    return int(parts[i + 1])
        return None
    except (ValueError, IndexError):
        return None

def merge_logcat_files(txt_files, output_file):
    """
    Merge multiple logcat buffer files into one, sorted by timestamp.
    Lines without timestamps are discarded.
    """
    all_lines = []
    
    for txt_file in txt_files:
        try:
            with open(txt_file, 'r', encoding='utf-8', errors='replace') as f:
                for line in f:
                    line = line.rstrip('\n\r')
                    timestamp = parse_logcat_timestamp(line)
                    if timestamp:
                        all_lines.append((timestamp, line))
        except Exception as e:
            print(f"Warning: Error reading {txt_file}: {e}")
    
    # Sort by timestamp
    all_lines.sort(key=lambda x: x[0])
    
    # Write to output file
    with open(output_file, 'w', encoding='utf-8') as f:
        for timestamp, line in all_lines:
            f.write(line + '\n')
    
    return len(all_lines)

def trim_pcap_file(pcap_file, start_ts, end_ts):
    """
    Trim pcap file to only include packets between start_ts and end_ts.
    Uses editcap (part of Wireshark/tshark) with frame.time (arrival time).
    
    Args:
        pcap_file: Input pcap file path (e.g., "base_name_tcpdump.pcap")
        start_ts: Start datetime object
        end_ts: End datetime object
    
    Returns:
        True if successful, False otherwise
    
    Output:
        Creates a new file with "_trimmed.pcap" suffix (e.g., "base_name_tcpdump_trimmed.pcap")
    """
    try:
        # Generate output filename: insert "_trimmed" before ".pcap"
        if pcap_file.endswith('.pcap'):
            output_file = pcap_file[:-5] + '_trimmed.pcap'
        else:
            output_file = pcap_file + '_trimmed.pcap'
        
        # Format timestamps for editcap: "YYYY-MM-DD HH:MM:SS.mmm"
        # editcap uses frame.time (arrival time) by default
        start_str = start_ts.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]  # Keep milliseconds
        end_str = end_ts.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
        
        # editcap command: editcap -A "start_time" -B "end_time" input.pcap output.pcap
        # -A: Keep packets AFTER this time (inclusive)
        # -B: Keep packets BEFORE this time (inclusive)
        cmd = ['editcap', '-A', start_str, '-B', end_str, pcap_file, output_file]
        
        result = subprocess.run(cmd, capture_output=True, text=True)
        
        if result.returncode == 0:
            print(f"  [✓] Trimmed PCAP: {os.path.basename(output_file)}")
            return True
        else:
            print(f"  [✗] editcap failed for {os.path.basename(pcap_file)}: {result.stderr.strip()}")
            return False
    except FileNotFoundError:
        print(f"  [✗] editcap not found. Please install Wireshark/tshark.")
        print(f"      Ubuntu/Debian: sudo apt-get install wireshark-common")
        print(f"      macOS: brew install wireshark")
        return False
    except Exception as e:
        print(f"  [✗] Error trimming PCAP {os.path.basename(pcap_file)}: {e}")
        return False

def find_timestamps_scenario_1_2(logcat_file, base_name, scenario, folder_path):
    """
    Find relevant timestamps for Scenario 1 and 2:
    1. START_DIALING: "DataCollector: === START_DIALING: Dialed ==="
    2. Call Blocked: "frida-{cs/ps}-call-blocker: Outgoing {CS/PS} call blocked!"
    3. Emergency IP: "RILJ    : [xxxx]< SETUP_DATA_CALL DataCallResponse:*" (closest before call blocked)
    """
    print(f"\n{'='*80}")
    print(f"Processing Experiment: {base_name}")
    print(f"Scenario: #{scenario}")
    print(f"{'='*80}")
    
    dialing_ts = None
    call_blocked_ts = None
    emergency_ip_ts = None
    
    setup_data_call_candidates = []  # Store all SETUP_DATA_CALL timestamps before call blocked
    
    try:
        with open(logcat_file, 'r', encoding='utf-8', errors='replace') as f:
            for line in f:
                timestamp = parse_logcat_timestamp(line)
                if not timestamp:
                    continue
                
                # Pattern 1: START_DIALING
                if 'DataCollector: === START_DIALING: Dialed ===' in line:
                    dialing_ts = timestamp
                    print(f"[✓] Found START_DIALING at: {timestamp.strftime('%m-%d %H:%M:%S.%f')[:-3]}")
                
                # Pattern 2: Call Blocked (case-insensitive cs/ps)
                if re.search(r'frida-[cp]s-call-blocker:.*Outgoing [CP]S call blocked!', line, re.IGNORECASE):
                    call_blocked_ts = timestamp
                    print(f"[✓] Found Call Blocked at: {timestamp.strftime('%m-%d %H:%M:%S.%f')[:-3]}")
                
                # Pattern 3: SETUP_DATA_CALL (collect all before call blocked)
                if re.search(r'RILJ\s*:\s*\[\d+\]<\s*SETUP_DATA_CALL\s+DataCallResponse:', line):
                    setup_data_call_candidates.append(timestamp)
                    
        
        # Find the closest SETUP_DATA_CALL before call_blocked_ts
        if call_blocked_ts and setup_data_call_candidates:
            # Filter: only those before call_blocked_ts
            valid_candidates = [ts for ts in setup_data_call_candidates if ts < call_blocked_ts]
            if valid_candidates:
                # Get the closest one (max timestamp that's still before call_blocked_ts)
                emergency_ip_ts = max(valid_candidates)
                print(f"[✓] Found Emergency IP (SETUP_DATA_CALL) at: {emergency_ip_ts.strftime('%m-%d %H:%M:%S.%f')[:-3]}")
        
        # Print results
        print(f"\n{'='*80}")
        print(f"Timestamps for Experiment {base_name}:")
        print(f"Scenario: #{scenario}")
        
        if dialing_ts:
            print(f"Dialing: {dialing_ts.strftime('%m-%d %H:%M:%S.%f')[:-3]}")
        else:
            print(f"Dialing: NOT FOUND")
        
        if emergency_ip_ts:
            print(f"Got Emergency IP: {emergency_ip_ts.strftime('%m-%d %H:%M:%S.%f')[:-3]}")
        else:
            print(f"Got Emergency IP: NOT FOUND")
        
        if call_blocked_ts:
            print(f"Call Blocked: {call_blocked_ts.strftime('%m-%d %H:%M:%S.%f')[:-3]}")
        else:
            print(f"Call Blocked: NOT FOUND")
        
        # Calculate time difference
        if dialing_ts and emergency_ip_ts:
            time_diff = (emergency_ip_ts - dialing_ts).total_seconds()
            print(f"Time from dialed out to the time that got emergency IP: {time_diff:.3f} seconds")
        else:
            print(f"Time from dialed out to the time that got emergency IP: CANNOT CALCULATE (missing timestamps)")
        
        print(f"{'='*80}\n")
        
        # ✅ Trim PCAP files if timestamps are available
        if dialing_ts and call_blocked_ts:
            print(f"Trimming PCAP files from {dialing_ts.strftime('%H:%M:%S.%f')[:-3]} to {call_blocked_ts.strftime('%H:%M:%S.%f')[:-3]}...")
            # Find all PCAP files matching this base_name
            pcap_found = False
            for filename in os.listdir(folder_path):
                if filename.startswith(base_name) and filename.endswith('.pcap') and not filename.endswith('_trimmed.pcap'):
                    pcap_file = os.path.join(folder_path, filename)
                    trim_pcap_file(pcap_file, dialing_ts, call_blocked_ts)
                    pcap_found = True
            
            if not pcap_found:
                print(f"  [!] No PCAP files found for {base_name}")
        else:
            print(f"[!] Cannot trim PCAP: missing dialing or call_blocked timestamp")
        
    except Exception as e:
        print(f"Error processing {logcat_file}: {e}")

def process_scenario_3(logcat_file, base_name, scenario, folder_path):
    """
    Process Scenario 3 (WiFi Calling)
    Find timestamps:
    1. START_DIALING: "DataCollector: === START_DIALING*"
    2. Receive SIP 180/183: "ImsPhoneCallTracker: [*] onCallProgressing"
    3. Call Blocked: "DataCollector: === CALL_BLOCKED*"
    """
    print(f"\n{'='*80}")
    print(f"Processing Experiment: {base_name}")
    print(f"Scenario: #{scenario}")
    print(f"{'='*80}")
    
    dialing_ts = None
    sip_ringing_ts = None
    call_blocked_ts = None
    
    try:
        with open(logcat_file, 'r', encoding='utf-8', errors='replace') as f:
            for line in f:
                timestamp = parse_logcat_timestamp(line)
                if not timestamp:
                    continue
                
                # Pattern 1: START_DIALING (any variant)
                if 'DataCollector: === START_DIALING_NORMAL: Dialed ===' in line:
                    dialing_ts = timestamp
                    print(f"[✓] Found START_DIALING at: {timestamp.strftime('%m-%d %H:%M:%S.%f')[:-3]}")
                
                # Pattern 2: SIP 180 Ringing / 183 Session Progress
                if re.search(r'ImsPhoneCallTracker:\s*\[.*\]\s*onCallProgressing', line):
                    sip_ringing_ts = timestamp
                    print(f"[✓] Found receive SIP 180 Ringing/183 Session Progressing at: {timestamp.strftime('%m-%d %H:%M:%S.%f')[:-3]}")
                
                # Pattern 3: Call Blocked
                if 'DataCollector: === CALL_BLOCKED' in line:
                    call_blocked_ts = timestamp
                    print(f"[✓] Found Call Blocked at: {timestamp.strftime('%m-%d %H:%M:%S.%f')[:-3]}")
        
        # Print results
        print(f"\n{'='*80}")
        print(f"Timestamps for Experiment {base_name}:")
        print(f"Scenario: #{scenario}")
        
        if dialing_ts:
            print(f"Dialing: {dialing_ts.strftime('%m-%d %H:%M:%S.%f')[:-3]}")
        else:
            print(f"Dialing: NOT FOUND")
        
        if sip_ringing_ts:
            print(f"Receive SIP 180 Ringing/183 Session Progressing: {sip_ringing_ts.strftime('%m-%d %H:%M:%S.%f')[:-3]}")
        else:
            print(f"Receive SIP 180 Ringing/183 Session Progressing: NOT FOUND")
        
        if call_blocked_ts:
            print(f"Call Blocked: {call_blocked_ts.strftime('%m-%d %H:%M:%S.%f')[:-3]}")
        else:
            print(f"Call Blocked: NOT FOUND")
        
        # Calculate time difference
        if dialing_ts and sip_ringing_ts:
            time_diff = (sip_ringing_ts - dialing_ts).total_seconds()
            print(f"Time from dialed out to receive SIP 180/183: {time_diff:.3f} seconds")
        else:
            print(f"Time from dialed out to receive SIP 180/183: CANNOT CALCULATE (missing timestamps)")
        
        print(f"{'='*80}\n")
        
        # ✅ Trim PCAP files if timestamps are available
        if dialing_ts and call_blocked_ts:
            print(f"Trimming PCAP files from {dialing_ts.strftime('%H:%M:%S.%f')[:-3]} to {call_blocked_ts.strftime('%H:%M:%S.%f')[:-3]}...")
            # Find all PCAP files matching this base_name
            pcap_found = False
            for filename in os.listdir(folder_path):
                if filename.startswith(base_name) and filename.endswith('.pcap') and not filename.endswith('_trimmed.pcap'):
                    pcap_file = os.path.join(folder_path, filename)
                    trim_pcap_file(pcap_file, dialing_ts, call_blocked_ts)
                    pcap_found = True
            
            if not pcap_found:
                print(f"  [!] No PCAP files found for {base_name}")
        else:
            print(f"[!] Cannot trim PCAP: missing dialing or call_blocked timestamp")
        
    except Exception as e:
        print(f"Error processing {logcat_file}: {e}")

def process_scenario_4(logcat_file, base_name, scenario, folder_path):
    """
    Process Scenario 4 (Satellite) - No PCAP trimming for now
    """
    print(f"\n{'='*80}")
    print(f"Processing Experiment: {base_name}")
    print(f"Scenario: #{scenario}")
    print(f"{'='*80}")
    print("Scenario #4: PCAP files left untrimmed (as requested).")
    print(f"{'='*80}\n")

def main():
    # Get folder path from command line argument or use current directory
    folder_path = sys.argv[1] if len(sys.argv) > 1 else './'
    
    if not os.path.isdir(folder_path):
        print(f"Error: '{folder_path}' is not a valid directory")
        sys.exit(1)
    
    print(f"Processing logs in: {os.path.abspath(folder_path)}")
    print(f"{'='*80}\n")
    
    # Step 1: Group .txt files by base name (timestamp identifier)
    txt_groups = defaultdict(list)
    
    for filename in os.listdir(folder_path):
        if filename.endswith('.txt'):
            filepath = os.path.join(folder_path, filename)
            base_name = extract_base_name(filename)
            txt_groups[base_name].append(filepath)
    
    if not txt_groups:
        print("No .txt files found in the specified directory.")
        sys.exit(0)
    
    print(f"Found {len(txt_groups)} unique timestamp groups")
    print(f"{'='*80}\n")
    
    # Step 2: Merge files for each group
    for base_name, txt_files in sorted(txt_groups.items()):
        print(f"Processing group: {base_name}")
        print(f"  Files: {len(txt_files)}")
        
        # Create output filename
        output_file = os.path.join(folder_path, f"{base_name}_logcat_all.txt")
        
        # Merge files
        line_count = merge_logcat_files(txt_files, output_file)
        print(f"  Merged {line_count} lines with timestamps -> {os.path.basename(output_file)}")
        
        # Extract scenario number
        scenario = extract_scenario_number(base_name)
        
        if scenario is None:
            print(f"  Warning: Could not extract scenario number from {base_name}")
            continue
        
        # Step 3: Process based on scenario
        if scenario in [1, 2]:
            find_timestamps_scenario_1_2(output_file, base_name, scenario, folder_path)
        elif scenario == 3:
            process_scenario_3(output_file, base_name, scenario, folder_path)
        elif scenario == 4:
            process_scenario_4(output_file, base_name, scenario, folder_path)
        else:
            print(f"  Warning: Unknown scenario number: {scenario}")
    
    print(f"\n{'='*80}")
    print("Processing complete!")
    print(f"{'='*80}")

if __name__ == "__main__":
    main()
