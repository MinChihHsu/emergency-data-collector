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
import csv
import shutil
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

def get_first_timestamp_from_logcat(logcat_file):
    """
    Get the first timestamp from logcat_all file.
    Returns datetime object or None if no timestamp found.
    """
    try:
        with open(logcat_file, 'r', encoding='utf-8', errors='replace') as f:
            for line in f:
                timestamp = parse_logcat_timestamp(line)
                if timestamp:
                    return timestamp
        return None
    except Exception as e:
        print(f"  [✗] Error reading first timestamp from {logcat_file}: {e}")
        return None

def normalize_base_name(base_name):
    """
    Normalize base name by merging Pixel model names.
    Example: 
        US_T-Mobile_Pixel_9_xxx -> US_T-Mobile_Pixel9_xxx
        US_T-Mobile_Pixel_10_xxx -> US_T-Mobile_Pixel10_xxx
        US_T-Mobile_SM-G9910_xxx -> US_T-Mobile_SM-G9910_xxx (unchanged)
    """
    parts = base_name.split('_')
    
    # Find Pixel model pattern: Pixel_{number}
    for i in range(len(parts) - 1):
        if parts[i] == 'Pixel' and parts[i + 1].isdigit():
            # Merge Pixel and number
            parts[i] = f'Pixel{parts[i + 1]}'
            parts.pop(i + 1)
            break
    
    return '_'.join(parts)

def extract_base_name(filename):
    """
    Extract base name (timestamp identifier) from filename.
    Example: 
        US_T-Mobile_Pixel_9_2e7b6568558a706f_20260204_1_1_164417_n42.710147_w84.458661_radio.txt
        -> US_T-Mobile_Pixel9_2e7b6568558a706f_20260204_1_1_164417_n42.710147_w84.458661
    """
    # Remove extension
    name_without_ext = filename.rsplit('.txt', 1)[0]
    
    # Remove buffer suffix (_radio, _main, _events, _system, _crash, _kernel)
    suffixes = ['_radio', '_main', '_events', '_system', '_crash', '_kernel']
    for suffix in suffixes:
        if name_without_ext.endswith(suffix):
            name_without_ext = name_without_ext[:-len(suffix)]
            break
    
    # Normalize Pixel model names
    return normalize_base_name(name_without_ext)

def extract_scenario_number(base_name):
    """
    Extract scenario number from base name.
    Format: {country}_{operator}_{model}_{deviceId}_{date}_{scenario}_{experiment}_{time}_{location}
    Example: US_T-Mobile_Pixel9_2e7b6568558a706f_20260204_1_1_164417_n42.710147_w84.458661
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

def extract_model_name(base_name):
    """
    Extract model name from base name.
    Format: {country}_{operator}_{model}_{deviceId}_{date}_{scenario}_{experiment}_{time}_{location}
    Example: US_T-Mobile_Pixel9_2e7b6568558a706f_20260204_1_1_164417_n42.710147_w84.458661
                         ^^^^^^^ model name
    """
    parts = base_name.split('_')
    # Model is typically at index 2
    if len(parts) >= 3:
        return parts[2]
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

def trim_pcap_file(pcap_file, start_ts, end_ts, output_dir):
    """
    Trim pcap file to only include packets between start_ts and end_ts.
    Uses editcap (part of Wireshark/tshark) with frame.time (arrival time).
    
    Args:
        pcap_file: Input pcap file path (e.g., "base_name_tcpdump.pcap")
        start_ts: Start datetime object
        end_ts: End datetime object
        output_dir: Directory to save trimmed pcap
    
    Returns:
        True if successful, False otherwise
    
    Output:
        Creates a new file with "_trimmed.pcap" suffix in output_dir
    """
    try:
        # Generate output filename: insert "_trimmed" before ".pcap"
        basename = os.path.basename(pcap_file)
        
        # Normalize basename (handle Pixel_X -> PixelX)
        basename_normalized = normalize_base_name(basename)
        
        if basename_normalized.endswith('.pcap'):
            output_filename = basename_normalized[:-5] + '_trimmed.pcap'
        else:
            output_filename = basename_normalized + '_trimmed.pcap'
        
        output_file = os.path.join(output_dir, output_filename)
        
        # Format timestamps for editcap: "YYYY-MM-DD HH:MM:SS.mmm"
        start_str = start_ts.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
        end_str = end_ts.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
        
        cmd = ['editcap', '-A', start_str, '-B', end_str, pcap_file, output_file]
        
        result = subprocess.run(cmd, capture_output=True, text=True)
        
        if result.returncode == 0:
            print(f"  [✓] Trimmed PCAP: {output_filename}")
            return True
        else:
            print(f"  [✗] editcap failed for {basename}: {result.stderr.strip()}")
            return False
    except FileNotFoundError:
        print(f"  [✗] editcap not found. Please install Wireshark/tshark.")
        return False
    except Exception as e:
        print(f"  [✗] Error trimming PCAP {os.path.basename(pcap_file)}: {e}")
        return False

def extract_operator_name(base_name):
    """
    Extract operator name from base name.
    Format: {country}_{operator}_{model}_{deviceId}_{date}_{scenario}_{experiment}_{time}_{location}
    Example: US_Verizon_Pixel9_2e7b6568558a706f_20260204_3_1_164417_n42.710147_w84.458661
                 ^^^^^^^^ operator name
    """
    parts = base_name.split('_')
    # Operator is typically at index 1
    if len(parts) >= 2:
        return parts[1]
    return None

def extract_sip_183_from_pcap(pcap_file, base_name):
    """
    Extract SIP 183 Session Progress or 180 Ringing frame arrival time from pcap file using tshark.
    - For Verizon: Search for SIP 180 Ringing
    - For other operators: Search for SIP 183 Session Progress
    Returns datetime object or None if not found.
    """
    try:
        # Determine which SIP status code to search for based on operator
        operator_name = extract_operator_name(base_name)
        
        if operator_name and 'verizon' in operator_name.lower():
            # Verizon: search for SIP 180 Ringing
            status_code = '180'
            status_text = 'Ringing'
            print(f"[i] Verizon detected, searching for SIP 180 Ringing...")
        else:
            # Other operators: search for SIP 183 Session Progress
            status_code = '183'
            status_text = 'Session Progress'
            print(f"[i] Searching for SIP 183 Session Progress...")
        
        # tshark command to find SIP status code
        # -r: read from file
        # -Y: display filter
        # -T fields -e frame.time_epoch: output frame arrival time as epoch
        cmd = [
            'tshark', '-r', pcap_file,
            '-Y', f'sip.Status-Code == {status_code}',
            '-T', 'fields', '-e', 'frame.time_epoch'
        ]
        
        result = subprocess.run(cmd, capture_output=True, text=True)
        
        if result.returncode == 0 and result.stdout.strip():
            # Get first match
            epoch_str = result.stdout.strip().split('\n')[0]
            epoch_float = float(epoch_str)
            return datetime.fromtimestamp(epoch_float)
        return None
    except Exception as e:
        print(f"  [✗] Error extracting SIP from PCAP: {e}")
        return None


def find_timestamps_scenario_1_2(logcat_file, base_name, scenario, folder_path, output_dir):
    """
    Find relevant timestamps for Scenario 1 and 2:
    1. START_DIALING: "=== START_DIALING: xxx (Scenario y) ===" (x=digits, y=1 or 2)
    2. Call Blocked: "frida-{cs/ps}-call-blocker: Outgoing {CS/PS} call blocked!" (with CS/PS type)
    3. Emergency IP: "RILJ    : [xxxx]< SETUP_DATA_CALL DataCallResponse:*" (all occurrences before call blocked)
    
    Returns: dict with keys: call_blocked (bool), call_blocked_type (str), call_blocked_time (float), 
             num_obtained_emc_ip (int), latest_emc_ip_time (float), wifi_call_time (None), 
             satellite_connected (None), satellite_modem_ready_time (None), satellite_connected_time (None)
    """
    print(f"\n{'='*80}")
    print(f"Processing Experiment: {base_name}")
    print(f"Scenario: #{scenario}")
    print(f"{'='*80}")
    
    dialing_ts = None
    call_blocked_ts = None
    call_blocked_type = None  # 'CS' or 'PS'
    emergency_ip_timestamps = []  # All SETUP_DATA_CALL timestamps
    
    try:
        with open(logcat_file, 'r', encoding='utf-8', errors='replace') as f:
            for line in f:
                timestamp = parse_logcat_timestamp(line)
                if not timestamp:
                    continue
                
                # Pattern 1: START_DIALING (updated pattern)
                if re.search(r'=== START_DIALING: \d+ \(Scenario [12]\) ===', line):
                    dialing_ts = timestamp
                    print(f"[✓] Found START_DIALING at: {timestamp.strftime('%m-%d %H:%M:%S.%f')[:-3]}")
                
                # Pattern 2: Call Blocked (capture CS/PS type)
                match = re.search(r'frida-([cp]s)-call-blocker:.*Outgoing ([CP]S) call blocked!', line, re.IGNORECASE)
                if match:
                    call_blocked_ts = timestamp
                    call_blocked_type = match.group(2).upper()  # 'CS' or 'PS'
                    print(f"[✓] Found Call Blocked ({call_blocked_type}) at: {timestamp.strftime('%m-%d %H:%M:%S.%f')[:-3]}")
                
                # Pattern 3: SETUP_DATA_CALL (collect all)
                if re.search(r'RILJ\s*:\s*\[\d+\]<\s*SETUP_DATA_CALL\s+DataCallResponse:', line):
                    emergency_ip_timestamps.append(timestamp)
        
        # Filter emergency IPs: only those before call_blocked_ts (if exists)
        if call_blocked_ts:
            emergency_ip_timestamps = [ts for ts in emergency_ip_timestamps if ts < call_blocked_ts]
        
        # Calculate num_obtained_emc_ip
        num_obtained_emc_ip = len(emergency_ip_timestamps)
        
        # Print results
        print(f"\n{'='*80}")
        print(f"Timestamps for Experiment {base_name}:")
        print(f"Scenario: #{scenario}")
        
        if dialing_ts:
            print(f"Dialing: {dialing_ts.strftime('%m-%d %H:%M:%S.%f')[:-3]}")
        else:
            print(f"Dialing: NOT FOUND")
        
        # Print emergency IP results
        if emergency_ip_timestamps:
            print(f"Got Emergency IP: {num_obtained_emc_ip} time(s)")
            for i, ts in enumerate(emergency_ip_timestamps, 1):
                print(f"  #{i}: {ts.strftime('%m-%d %H:%M:%S.%f')[:-3]}")
        else:
            print(f"Got Emergency IP: NOT FOUND")
        
        if call_blocked_ts:
            print(f"Call Blocked ({call_blocked_type}): {call_blocked_ts.strftime('%m-%d %H:%M:%S.%f')[:-3]}")
        else:
            print(f"Call Blocked: NOT FOUND")
        
        # Calculate time differences
        latest_emc_ip_time = None
        call_blocked_time = None
        
        if call_blocked_ts and dialing_ts:
            call_blocked_time = (call_blocked_ts - dialing_ts).total_seconds()
        
        if call_blocked_ts and emergency_ip_timestamps:
            # Case 1: Has blocked + has emergency IP
            # Use closest IP before blocked
            closest_ip = max(emergency_ip_timestamps)
            time_diff = (closest_ip - dialing_ts).total_seconds() if dialing_ts else None
            if time_diff is not None:
                latest_emc_ip_time = time_diff
                print(f"Time from dialed out to the time that got emergency IP: {time_diff:.3f} seconds")
                print(f"Time from dialed out to the time that the call is blocked: {call_blocked_time:.3f} seconds")
        elif call_blocked_ts and not emergency_ip_timestamps:
            # Case 2: Has blocked but no emergency IP
            print(f"Time from dialed out to the time that got emergency IP: N/A (No emergency IP obtained)")
            if call_blocked_time is not None:
                print(f"Time from dialed out to the time that the call is blocked: {call_blocked_time:.3f} seconds")
        elif not call_blocked_ts and emergency_ip_timestamps:
            # Case 3: No blocked but has emergency IP
            print(f"Time from dialed out to the time that got emergency IP: N/A (Call is not sent out.)")
            print(f"The phone got {num_obtained_emc_ip} new IP(s), but the call never dialed out.")
        else:
            # Case 4: No blocked and no emergency IP
            print(f"Time from dialed out to the time that got emergency IP: N/A (No emergency IP obtained)")
            print(f"The phone did not get any emergency IP during the call.")
        
        print(f"{'='*80}\n")
        
        # Trim PCAP files - use first timestamp from logcat_all as start_ts
        first_ts = get_first_timestamp_from_logcat(logcat_file)
        if first_ts and call_blocked_ts:
            print(f"Trimming PCAP files from {first_ts.strftime('%H:%M:%S.%f')[:-3]} to {call_blocked_ts.strftime('%H:%M:%S.%f')[:-3]}...")
            pcap_found = False
            for filename in os.listdir(folder_path):
                # Match original filename (with Pixel_X pattern)
                original_base = filename
                for suffix in ['_tcpdump.pcap', '_scat.pcap', '.pcap']:
                    if filename.endswith(suffix):
                        original_base = filename[:-len(suffix)]
                        break
                
                # Normalize and compare
                if normalize_base_name(original_base) == base_name and filename.endswith('.pcap') and not filename.endswith('_trimmed.pcap'):
                    pcap_file = os.path.join(folder_path, filename)
                    trim_pcap_file(pcap_file, first_ts, call_blocked_ts, output_dir)
                    pcap_found = True
            
            if not pcap_found:
                print(f"  [!] No PCAP files found for {base_name}")
        else:
            print(f"[!] Cannot trim PCAP: missing first timestamp or call_blocked timestamp")
        
        # Return CSV data
        return {
            'call_blocked': call_blocked_ts is not None,
            'call_blocked_type': call_blocked_type if call_blocked_ts else None,
            'call_blocked_time': call_blocked_time,
            'num_obtained_emc_ip': num_obtained_emc_ip,
            'latest_emc_ip_time': latest_emc_ip_time,
            'wifi_call_time': None,
            'satellite_connected': None,
            'satellite_modem_ready_time': None,
            'satellite_connected_time': None
        }
        
    except Exception as e:
        print(f"Error processing {logcat_file}: {e}")
        return {
            'call_blocked': None, 
            'call_blocked_type': None, 
            'call_blocked_time': None,
            'num_obtained_emc_ip': None,
            'latest_emc_ip_time': None, 
            'wifi_call_time': None,
            'satellite_connected': None,
            'satellite_modem_ready_time': None,
            'satellite_connected_time': None
        }

def process_scenario_3(logcat_file, base_name, scenario, folder_path, output_dir):
    """
    Process Scenario 3 (WiFi Calling)
    Find timestamps:
    1. START_DIALING: "DataCollector: === START_DIALING*"
    2. Receive SIP 180/183:
       - Samsung (SM-*): Search in logcat for "SIPMSG[x]: [<--] SIP/a.a 183 Session Progress"
       - Pixel: Extract from pcap using tshark (180 for Verizon, 183 for others)
    
    Returns: dict with keys: call_blocked (None), call_blocked_type (None), call_blocked_time (None),
             num_obtained_emc_ip (None), latest_emc_ip_time (None), wifi_call_time (float),
             satellite_connected (None), satellite_modem_ready_time (None), satellite_connected_time (None)
    """
    print(f"\n{'='*80}")
    print(f"Processing Experiment: {base_name}")
    print(f"Scenario: #{scenario}")
    print(f"{'='*80}")
    
    dialing_ts = None
    sip_ringing_ts = None
    call_blocked_ts = None
    
    model_name = extract_model_name(base_name)
    is_samsung = model_name and model_name.startswith('SM')
    
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
                
                # Pattern 2: SIP 183 (Samsung only - from logcat)
                if is_samsung and re.search(r'SIPMSG\[\d+\]:\s*\[<--\]\s*SIP/\d\.\d\s+183\s+Session Progress', line):
                    sip_ringing_ts = timestamp
                    print(f"[✓] Found SIP 183 Session Progress (from logcat) at: {timestamp.strftime('%m-%d %H:%M:%S.%f')[:-3]}")
                
                # Pattern 3: Call Blocked
                if 'DataCollector: === CALL_BLOCKED' in line:
                    call_blocked_ts = timestamp
                    print(f"[✓] Found Call Blocked at: {timestamp.strftime('%m-%d %H:%M:%S.%f')[:-3]}")
        
        # For Pixel: extract SIP 180/183 from pcap
        if not is_samsung and not sip_ringing_ts:
            print(f"[i] Pixel device detected, extracting SIP from PCAP...")
            for filename in os.listdir(folder_path):
                # Match original filename (with Pixel_X pattern)
                original_base = filename
                for suffix in ['_tcpdump.pcap', '_scat.pcap', '.pcap']:
                    if filename.endswith(suffix):
                        original_base = filename[:-len(suffix)]
                        break
                
                # Normalize and compare
                if normalize_base_name(original_base) == base_name and filename.endswith('.pcap') and not filename.endswith('_trimmed.pcap'):
                    pcap_file = os.path.join(folder_path, filename)
                    sip_ringing_ts = extract_sip_183_from_pcap(pcap_file, base_name)  # ✅ Pass base_name
                    if sip_ringing_ts:
                        operator_name = extract_operator_name(base_name)
                        if operator_name and 'verizon' in operator_name.lower():
                            print(f"[✓] Found SIP 180 Ringing (from PCAP) at: {sip_ringing_ts.strftime('%m-%d %H:%M:%S.%f')[:-3]}")
                        else:
                            print(f"[✓] Found SIP 183 Session Progress (from PCAP) at: {sip_ringing_ts.strftime('%m-%d %H:%M:%S.%f')[:-3]}")
                        break
        
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
        
        # Calculate time difference
        wifi_call_time = None
        if dialing_ts and sip_ringing_ts:
            time_diff = (sip_ringing_ts - dialing_ts).total_seconds()
            wifi_call_time = time_diff
            print(f"Time from dialed out to receive SIP 180/183: {time_diff:.3f} seconds")
        else:
            print(f"Time from dialed out to receive SIP 180/183: CANNOT CALCULATE (missing timestamps)")
        
        print(f"{'='*80}\n")
        
        # Trim PCAP files - use first timestamp from logcat_all as start_ts
        first_ts = get_first_timestamp_from_logcat(logcat_file)
        if first_ts and call_blocked_ts:
            print(f"Trimming PCAP files from {first_ts.strftime('%H:%M:%S.%f')[:-3]} to {call_blocked_ts.strftime('%H:%M:%S.%f')[:-3]}...")
            pcap_found = False
            for filename in os.listdir(folder_path):
                # Match original filename (with Pixel_X pattern)
                original_base = filename
                for suffix in ['_tcpdump.pcap', '_scat.pcap', '.pcap']:
                    if filename.endswith(suffix):
                        original_base = filename[:-len(suffix)]
                        break
                
                # Normalize and compare
                if normalize_base_name(original_base) == base_name and filename.endswith('.pcap') and not filename.endswith('_trimmed.pcap'):
                    pcap_file = os.path.join(folder_path, filename)
                    trim_pcap_file(pcap_file, first_ts, call_blocked_ts, output_dir)
                    pcap_found = True
            
            if not pcap_found:
                print(f"  [!] No PCAP files found for {base_name}")
        else:
            print(f"[!] Cannot trim PCAP: missing first timestamp or call_blocked timestamp")
        
        # Return CSV data
        return {
            'call_blocked': None,
            'call_blocked_type': None,
            'call_blocked_time': None,
            'num_obtained_emc_ip': None,
            'latest_emc_ip_time': None,
            'wifi_call_time': wifi_call_time,
            'satellite_connected': None,
            'satellite_modem_ready_time': None,
            'satellite_connected_time': None
        }
        
    except Exception as e:
        print(f"Error processing {logcat_file}: {e}")
        return {
            'call_blocked': None, 
            'call_blocked_type': None, 
            'call_blocked_time': None,
            'num_obtained_emc_ip': None,
            'latest_emc_ip_time': None, 
            'wifi_call_time': None,
            'satellite_connected': None,
            'satellite_modem_ready_time': None,
            'satellite_connected_time': None
        }


def process_scenario_4(logcat_file, base_name, scenario, folder_path, output_dir):
    """
    Process Scenario 4 (Satellite)
    Find timestamps:
    1. starting_ts: "......SatelliteMonitor: Service started,......"
    2. modem_ready_ts: "SG-APK-Telephony: SatelliteStateCallback#onSatelliteModemStateChanged: SATELLITE_MODEM_STATE_NOT_CONNECTED"
    3. connected_ts: "SG-APK-Telephony: SatelliteStateCallback#onSatelliteModemStateChanged: SATELLITE_MODEM_STATE_CONNECTED"
    
    Returns: dict with keys: call_blocked (None), call_blocked_type (None), call_blocked_time (None),
             num_obtained_emc_ip (None), latest_emc_ip_time (None), wifi_call_time (None),
             satellite_connected (bool), satellite_modem_ready_time (float), satellite_connected_time (float)
    """
    print(f"\n{'='*80}")
    print(f"Processing Experiment: {base_name}")
    print(f"Scenario: #{scenario}")
    print(f"{'='*80}")
    
    starting_ts = None
    modem_ready_ts = None
    connected_ts = None
    
    try:
        with open(logcat_file, 'r', encoding='utf-8', errors='replace') as f:
            for line in f:
                timestamp = parse_logcat_timestamp(line)
                if not timestamp:
                    continue
                
                # Pattern 1: Service started
                if 'SatelliteMonitor: Service started' in line:
                    starting_ts = timestamp
                    print(f"[✓] Found Service started at: {timestamp.strftime('%m-%d %H:%M:%S.%f')[:-3]}")
                
                # Pattern 2: Modem ready (NOT_CONNECTED state)
                if 'SG-APK-Telephony: SatelliteStateCallback#onSatelliteModemStateChanged: SATELLITE_MODEM_STATE_NOT_CONNECTED' in line:
                    modem_ready_ts = timestamp
                    print(f"[✓] Found Modem Ready (NOT_CONNECTED) at: {timestamp.strftime('%m-%d %H:%M:%S.%f')[:-3]}")
                
                # Pattern 3: Connected
                if 'SG-APK-Telephony: SatelliteStateCallback#onSatelliteModemStateChanged: SATELLITE_MODEM_STATE_CONNECTED' in line:
                    connected_ts = timestamp
                    print(f"[✓] Found Satellite Connected at: {timestamp.strftime('%m-%d %H:%M:%S.%f')[:-3]}")
        
        # Calculate time differences
        satellite_connected = connected_ts is not None
        satellite_modem_ready_time = None
        satellite_connected_time = None
        
        if starting_ts and modem_ready_ts:
            satellite_modem_ready_time = (modem_ready_ts - starting_ts).total_seconds()
            print(f"Satellite Modem Ready Time: {satellite_modem_ready_time:.3f} seconds")
        
        if starting_ts and connected_ts:
            satellite_connected_time = (connected_ts - starting_ts).total_seconds()
            print(f"Satellite Connected Time: {satellite_connected_time:.3f} seconds")
        
        print(f"{'='*80}\n")
        
        # Return CSV data
        return {
            'call_blocked': None,
            'call_blocked_type': None,
            'call_blocked_time': None,
            'num_obtained_emc_ip': None,
            'latest_emc_ip_time': None,
            'wifi_call_time': None,
            'satellite_connected': satellite_connected,
            'satellite_modem_ready_time': satellite_modem_ready_time,
            'satellite_connected_time': satellite_connected_time
        }
        
    except Exception as e:
        print(f"Error processing {logcat_file}: {e}")
        return {
            'call_blocked': None, 
            'call_blocked_type': None, 
            'call_blocked_time': None,
            'num_obtained_emc_ip': None,
            'latest_emc_ip_time': None, 
            'wifi_call_time': None,
            'satellite_connected': None,
            'satellite_modem_ready_time': None,
            'satellite_connected_time': None
        }

def main():
    # Get folder path from command line argument or use current directory
    folder_path = sys.argv[1] if len(sys.argv) > 1 else './'
    
    if not os.path.isdir(folder_path):
        print(f"Error: '{folder_path}' is not a valid directory")
        sys.exit(1)
    
    # Create post-process directory
    output_dir = os.path.join(folder_path, 'post-process')
    os.makedirs(output_dir, exist_ok=True)
    
    print(f"Processing logs in: {os.path.abspath(folder_path)}")
    print(f"Output directory: {os.path.abspath(output_dir)}")
    print(f"{'='*80}\n")
    
    # Step 1: Group .txt files by base name (timestamp identifier)
    # ✅ Exclude _ipsec_info.txt and _logcat_all.txt files
    txt_groups = defaultdict(list)
    
    for filename in os.listdir(folder_path):
        if filename.endswith('.txt') and not filename.endswith('_logcat_all.txt') and not filename.endswith('_ipsec_info.txt'):
            filepath = os.path.join(folder_path, filename)
            base_name = extract_base_name(filename)
            txt_groups[base_name].append(filepath)
    
    if not txt_groups:
        print("No .txt files found in the specified directory.")
        sys.exit(0)
    
    print(f"Found {len(txt_groups)} unique timestamp groups")
    print(f"{'='*80}\n")
    
    # CSV data storage
    csv_data = []
    
    # Step 2: Merge files for each group and process
    for base_name, txt_files in sorted(txt_groups.items()):
        print(f"Processing group: {base_name}")
        print(f"  Files: {len(txt_files)}")
        
        # Create output filename in post-process directory
        output_file = os.path.join(output_dir, f"{base_name}_logcat_all.txt")
        
        # Merge files
        line_count = merge_logcat_files(txt_files, output_file)
        print(f"  Merged {line_count} lines with timestamps -> {os.path.basename(output_file)}")
        
        # Extract scenario number
        scenario = extract_scenario_number(base_name)
        
        if scenario is None:
            print(f"  Warning: Could not extract scenario number from {base_name}")
            csv_data.append({
                'basefilename': base_name,
                'call_blocked': None,
                'call_blocked_type': None,
                'call_blocked_time': None,
                'num_obtained_emc_ip': None,
                'latest_emc_ip_time': None,
                'wifi_call_time': None,
                'satellite_connected': None,
                'satellite_modem_ready_time': None,
                'satellite_connected_time': None
            })
            continue
        
        # Step 3: Process based on scenario
        result = None
        if scenario in [1, 2]:
            result = find_timestamps_scenario_1_2(output_file, base_name, scenario, folder_path, output_dir)
        elif scenario == 3:
            result = process_scenario_3(output_file, base_name, scenario, folder_path, output_dir)
        elif scenario == 4:
            result = process_scenario_4(output_file, base_name, scenario, folder_path, output_dir)
        else:
            print(f"  Warning: Unknown scenario number: {scenario}")
            result = {
                'call_blocked': None, 
                'call_blocked_type': None, 
                'call_blocked_time': None,
                'num_obtained_emc_ip': None,
                'latest_emc_ip_time': None, 
                'wifi_call_time': None,
                'satellite_connected': None,
                'satellite_modem_ready_time': None,
                'satellite_connected_time': None
            }
        
        # Add to CSV data
        csv_data.append({
            'basefilename': base_name,
            **result
        })
        
        # Copy .pftrace files to post-process directory (with normalized name)
        for filename in os.listdir(folder_path):
            if filename.endswith('.pftrace'):
                # Check if this file belongs to current base_name
                file_base = filename.rsplit('.pftrace', 1)[0]
                if normalize_base_name(file_base) == base_name:
                    src = os.path.join(folder_path, filename)
                    # Use normalized name for destination
                    dst = os.path.join(output_dir, f"{base_name}.pftrace")
                    shutil.copy2(src, dst)
                    print(f"  [✓] Copied: {filename} -> {base_name}.pftrace")
        
        # Copy _ipsec_info.txt files to post-process directory (with normalized name)
        for filename in os.listdir(folder_path):
            if filename.endswith('_ipsec_info.txt'):
                # Check if this file belongs to current base_name
                file_base = filename.rsplit('_ipsec_info.txt', 1)[0]
                if normalize_base_name(file_base) == base_name:
                    src = os.path.join(folder_path, filename)
                    # Use normalized name for destination
                    dst = os.path.join(output_dir, f"{base_name}_ipsec_info.txt")
                    shutil.copy2(src, dst)
                    print(f"  [✓] Copied: {filename} -> {base_name}_ipsec_info.txt")
    
    # Step 4: Write CSV summary
    csv_file = os.path.join(output_dir, 'summary.csv')
    with open(csv_file, 'w', newline='', encoding='utf-8') as f:
        fieldnames = ['basefilename', 'call_blocked', 'call_blocked_type', 'call_blocked_time', 
                     'num_obtained_emc_ip', 'latest_emc_ip_time', 'wifi_call_time',
                     'satellite_connected', 'satellite_modem_ready_time', 'satellite_connected_time']
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        
        for row in csv_data:
            # Convert boolean to true/false string
            for bool_key in ['call_blocked', 'satellite_connected']:
                if row[bool_key] is not None:
                    row[bool_key] = 'true' if row[bool_key] else 'false'
                else:
                    row[bool_key] = 'null'
            
            # Convert None to 'null' string for CSV
            for key in ['call_blocked_type', 'call_blocked_time', 'num_obtained_emc_ip', 
                       'latest_emc_ip_time', 'wifi_call_time', 
                       'satellite_modem_ready_time', 'satellite_connected_time']:
                if row[key] is None:
                    row[key] = 'null'
            
            writer.writerow(row)
    
    print(f"\n{'='*80}")
    print(f"CSV summary written to: {csv_file}")
    print(f"All output files saved to: {output_dir}")
    print(f"{'='*80}")
    print("Processing complete!")
    print(f"{'='*80}")

if __name__ == "__main__":
    main()
