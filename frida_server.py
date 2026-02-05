#!/usr/bin/env python3
"""
run on Mac/Ubuntu

1. pip install flask
2. sudo python frida_server.py (sudo for scat)
3. adb reverse tcp:5555 tcp:5555
4. adb run frida-server on cellphone (for now)
5. Grant this app as an superuser in Magisk(for am command)

* check the DIR of scripts first
* TODO: revise to python arguments
"""

from flask import Flask, jsonify, request
import subprocess
import os
import signal
import time
import re
import select  # NEW
import fcntl

app = Flask(__name__)

###  ---- USER SET VARIABLES ----
# Directory of where frida scripts are located.
SCRIPT_DIR = "scripts"
# Output directory for scat pcap files
SCAT_OUTPUT_DIR = "scat_output"


# Samsung S21 Frida scripts
S21_GSM_DIAL_SCRIPT = os.path.join(SCRIPT_DIR, "s21_void_gsm_dial.js")
S21_USERAGENT_SCRIPT = os.path.join(SCRIPT_DIR, "s21_void_useragent.js")

# Pixel 9 Frida scripts
PIXEL_GSM_DIAL_SCRIPT = os.path.join(SCRIPT_DIR, "pixel9_void_gsm_dial.js")
PIXEL_CALLSESSION_SCRIPT = os.path.join(SCRIPT_DIR, "pixel9_void_callsessionadaptor.js")

# Pixel Satellite Frida script
PIXEL_SATELLITE_BLOCK_DATAGRAM_SCRIPT = os.path.join(SCRIPT_DIR, "pixel_satellite_block_datagram.js")


# USB Vendor IDs for different modem types
USB_VENDOR_IDS = {
    "qc": "05c6",      # Qualcomm
    "sec": "04e8",     # Google Pixel (uses sec modem but Google USB ID)
    "mtk": "0e8d",     # MediaTek
}

# Current device type (set by /start-frida request)
current_device_type = "samsung"  # "samsung" or "pixel"

frida_processes = []
scat_process = None


def wait_for_marker(proc, marker, timeout_s=2.0):
    """
    Robust marker wait:
    - reads raw bytes from the underlying fd (os.read)
    - does not depend on newline
    - avoids TextIOWrapper buffering gotchas
    """
    if proc.stdout is None:
        return False, ""

    fd = proc.stdout.fileno()

    # set non-blocking on fd
    fl = fcntl.fcntl(fd, fcntl.F_GETFL)
    fcntl.fcntl(fd, fcntl.F_SETFL, fl | os.O_NONBLOCK)

    marker_b = marker.encode("utf-8", errors="ignore")
    buf = b""
    end = time.monotonic() + timeout_s

    while time.monotonic() < end:
        if proc.poll() is not None:
            text = buf.decode("utf-8", errors="replace")
            tail = re.split(r"[\r\n]+", text)
            return False, "\n".join(tail[-80:]) + f"\n(process exited rc={proc.returncode})"

        r, _, _ = select.select([fd], [], [], 0.1)
        if not r:
            continue

        try:
            chunk = os.read(fd, 4096)
        except BlockingIOError:
            continue

        if not chunk:
            continue
        
        
        buf += chunk

        if marker_b in buf:
            text = buf.decode("utf-8", errors="replace")
            print('frida output: ', text)
            tail = re.split(r"[\r\n]+", text)
            return True, "\n".join(tail[-80:])

        if b"FRIDA_ERROR:" in buf:
            text = buf.decode("utf-8", errors="replace")
            tail = re.split(r"[\r\n]+", text)
            return False, "\n".join(tail[-80:])

        # prevent unbounded growth
        if len(buf) > 300_000:
            buf = buf[-80_000:]

    text = buf.decode("utf-8", errors="replace")
    tail = re.split(r"[\r\n]+", text)
    return False, "\n".join(tail[-80:])


def kill_frida_processes():
    global frida_processes
    for proc in frida_processes:
        try:
            proc.terminate()
            proc.wait(timeout=2)
        except:
            try:
                proc.kill()
            except:
                pass
    frida_processes = []

    subprocess.run(['killall', 'frida'], capture_output=True)


def start_frida_scripts(device_type="samsung"):
    """
    Start Frida scripts based on device type.
    device_type: "samsung" or "pixel"

    Success criteria (stronger):
    - both frida processes started
    - both scripts printed their FRIDA_READY:<script_id> marker within 2s
    """
    global frida_processes, current_device_type
    current_device_type = device_type

    kill_frida_processes()
    time.sleep(0.5)

    if device_type == "pixel":
        print(f"Starting Frida for Pixel device...")

        # gsm_dial for Pixel
        try:
            proc1 = subprocess.Popen(
                ['frida', '-U', '-n', 'com.android.phone', '-l', PIXEL_GSM_DIAL_SCRIPT],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=False,
                bufsize=0
            )
            frida_processes.append(proc1)
            print(f"Started frida for com.android.phone (Pixel) (PID: {proc1.pid})")
        except Exception as e:
            print(f"Error starting Pixel gsm_dial script: {e}")
            return False

        time.sleep(1)

        # callsessionadaptor for Pixel (using com.shannon.imsservice)
        try:
            proc2 = subprocess.Popen(
                ['frida', '-U', '-n', 'com.shannon.imsservice', '-l', PIXEL_CALLSESSION_SCRIPT],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=False,
                bufsize=0
            )
            frida_processes.append(proc2)
            print(f"Started frida for com.shannon.imsservice (Pixel) (PID: {proc2.pid})")
        except Exception as e:
            print(f"Error starting Pixel callsession script: {e}")
            return False

        # NEW: wait for ready markers (2s timeout each)
        ok1, out1 = wait_for_marker(proc1, "FRIDA_READY:pixel9_void_gsm_dial", timeout_s=2.0)
        ok2, out2 = wait_for_marker(proc2, "FRIDA_READY:pixel9_void_callsessionadaptor", timeout_s=2.0)

        if not (ok1 and ok2):
            print("Frida ready timeout or failure (Pixel).")
            print("proc1 tail:\n", out1)
            print("proc2 tail:\n", out2)
            return False

    else:
        # Samsung S21 scripts (default)
        print(f"Starting Frida for Samsung device...")

        # gsm_dial for Samsung
        try:
            proc1 = subprocess.Popen(
                ['frida', '-U', '-n', 'com.android.phone', '-l', S21_GSM_DIAL_SCRIPT],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=False,
                bufsize=0
            )
            frida_processes.append(proc1)
            print(f"Started frida for com.android.phone (Samsung) (PID: {proc1.pid})")
        except Exception as e:
            print(f"Error starting Samsung gsm_dial script: {e}")
            return False

        time.sleep(1)
    # 'stdbuf', '-oL', '-eL', 
        # useragent for Samsung
        try:
            proc2 = subprocess.Popen(
                ['frida', '-U', '-n', 'com.sec.imsservice', '-l', S21_USERAGENT_SCRIPT],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=False,
                bufsize=0
            )
            frida_processes.append(proc2)
            print(f"Started frida for com.sec.imsservice (Samsung) (PID: {proc2.pid})")
        except Exception as e:
            print(f"Error starting Samsung useragent script: {e}")
            return False

        # NEW: wait for ready markers (2s timeout each)
        ok1, out1 = wait_for_marker(proc1, "FRIDA_READY:s21_void_gsm_dial", timeout_s=2.0)
        ok2, out2 = wait_for_marker(proc2, "FRIDA_READY:s21_void_useragent", timeout_s=2.0)

        if not (ok1 and ok2):
            print("Frida ready timeout or failure (Samsung).")
            print("ok1:", ok1, ", ok2:", ok2  )
            print("proc1 tail:\n", out1)
            print("proc2 tail:\n", out2)
            return False

    return True

def start_frida_satellite():
    """
    Start Frida satellite blocker script:
      frida -U -n com.android.phone -l $SCRIPT_DIR/pixel_satellite_block_datagram.js

    Success criteria (stronger):
    - frida process started
    - script printed its FRIDA_READY marker within 2s
    """
    global frida_processes

    kill_frida_processes()
    time.sleep(0.5)

    print("Starting Frida satellite script...")

    try:
        proc = subprocess.Popen(
            ['frida', '-U', '-n', 'com.android.phone', '-l', PIXEL_SATELLITE_BLOCK_DATAGRAM_SCRIPT],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=False,
            bufsize=0
        )
        frida_processes.append(proc)
        print(f"Started frida satellite for com.android.phone (PID: {proc.pid})")
    except Exception as e:
        print(f"Error starting satellite frida script: {e}")
        return False

    ok, out = wait_for_marker(proc, "FRIDA_READY:pixel_satellite_block_datagram", timeout_s=2.0)
    if not ok:
        print("Frida ready timeout or failure (Satellite).")
        print("proc tail:\n", out)
        return False

    return True



def find_usb_port(modem_type):
    """
    Find USB port for the specified modem type using lsusb.
    Returns port in format "BUS:DEVICE" (e.g., "003:013")
    TODO: Better way?
    """
    vendor_id = USB_VENDOR_IDS.get(modem_type, "05c6")  # Default to Qualcomm

    try:
        result = subprocess.run(['lsusb'], capture_output=True, text=True)
        lines = result.stdout.strip().split('\n')

        for line in lines:
            if vendor_id in line.lower():
                # Parse: "Bus 003 Device 013: ID 05c6:9091 Qualcomm, Inc. ..."
                match = re.match(r'Bus (\d+) Device (\d+):', line)
                if match:
                    bus = match.group(1)
                    device = match.group(2)
                    port = f"{bus}:{device}"
                    print(f"Found USB device for {modem_type}: {port}")
                    return port

        print(f"No USB device found for modem type: {modem_type} (vendor: {vendor_id})")
        return None
    except Exception as e:
        print(f"Error running lsusb: {e}")
        return None


def start_scat(modem_type, filename):
    """
    Start scat process to capture cellular signaling.
    Command for qc: sudo scat -t qc -u -a <port> -i 0 -F <filename>
    Command for sec (Pixel): sudo scat -t sec -u -a <port> -i 0 --start-magic 0x34dc12fe -F <filename>
    """
    global scat_process

    # IMPORTANT: Force kill any existing scat processes first
    print("Force killing any existing scat processes...")
    stop_scat_process()
    time.sleep(2)  # Wait longer for USB resource cleanup

    # Double check - pkill any orphan scat
    subprocess.run(['sudo', 'pkill', '-9', 'scat'], capture_output=True)
    time.sleep(1)  # Wait for OS to release USB

    # Find USB port
    usb_port = find_usb_port(modem_type)
    if not usb_port:
        print("ERROR: USB port not found!")
        return False, "USB port not found"

    # Ensure output directory exists
    os.makedirs(SCAT_OUTPUT_DIR, exist_ok=True)

    # Build full path for output file
    output_file = os.path.join(SCAT_OUTPUT_DIR, filename)

    # Check if file already exists (shouldn't happen, but just in case)
    if os.path.exists(output_file):
        print(f"WARNING: File already exists: {output_file}")

    # Build scat command based on modem type
    # For sec (Pixel/Exynos): add --start-magic flag
    if modem_type == "sec":
        cmd = ['sudo', 'scat', '-t', modem_type, '-u', '-L', 'ip,nas,rrc,pdcp,rlc,mac', '-a', usb_port, '-i', '0',
               '--start-magic', '0x34dc12fe', '-F', output_file]
    else:
        cmd = ['sudo', 'scat', '-t', modem_type, '-u', '-L', 'ip,nas,rrc,pdcp,rlc,mac', '-a', usb_port, '-i', '0', '-F', output_file]

    print(f"Starting scat: {' '.join(cmd)}")

    try:
        scat_process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )
        print(f"scat started (PID: {scat_process.pid})")

        # Wait a moment to check if process started successfully
        time.sleep(1.0)
        if scat_process.poll() is not None:
            # Process already terminated - something went wrong
            stderr = scat_process.stderr.read().decode() if scat_process.stderr else ""
            print(f"ERROR: scat terminated immediately! stderr: {stderr}")
            return False, f"scat failed to start: {stderr}"

        # Wait additional time for scat to stabilize and start capturing
        print("Waiting for scat to stabilize...")
        time.sleep(2)  # Give scat time to actually start recording

        print(f"scat running and ready (PID: {scat_process.pid})")
        return True, f"scat started, output: {output_file}"
    except Exception as e:
        print(f"Error starting scat: {e}")
        return False, str(e)


def stop_scat_process():
    """
    Stop scat process by sending SIGINT (Ctrl+C)
    Uses sudo kill to ensure signal reaches scat even through sudo wrapper
    """
    global scat_process

    if scat_process is not None:
        pid = scat_process.pid
        print(f"Stopping scat (PID: {pid})...")

        try:
            # Method 1: Use sudo pkill to send SIGINT to scat directly (most reliable)
            # This bypasses the sudo wrapper issue
            print("Sending SIGINT via sudo pkill...")
            subprocess.run(['sudo', 'pkill', '-INT', '-f', 'scat'], capture_output=True, timeout=3)

            # Wait for our process to finish
            scat_process.wait(timeout=8)  # Give more time for file flush
            print(f"scat stopped gracefully (PID: {pid})")

        except subprocess.TimeoutExpired:
            print(f"scat timeout after SIGINT, sending SIGTERM...")
            try:
                # Try SIGTERM
                subprocess.run(['sudo', 'pkill', '-TERM', '-f', 'scat'], capture_output=True, timeout=2)
                scat_process.wait(timeout=3)
                print("scat stopped with SIGTERM")
            except:
                # Last resort: SIGKILL
                print(f"scat still not responding, force killing (SIGKILL)...")
                subprocess.run(['sudo', 'pkill', '-9', '-f', 'scat'], capture_output=True)
                try:
                    scat_process.wait(timeout=2)
                except:
                    pass
                print("scat killed (force)")

        except Exception as e:
            print(f"Error stopping scat: {e}")
        finally:
            scat_process = None
    else:
        print("No scat process to stop")
        # Still try to clean up any orphan processes
        subprocess.run(['sudo', 'pkill', '-INT', '-f', 'scat'], capture_output=True)


@app.route('/start-frida', methods=['POST'])
def start_frida():
    print("\n=== Received: /start-frida ===")

    data = request.get_json() or {}
    device_type = data.get('device_type', 'samsung')
    print(f"Device type: {device_type}")

    success = start_frida_scripts(device_type)
    if success:
        return jsonify({"status": "ok", "message": f"Frida scripts started for {device_type}"}), 200
    else:
        return jsonify({"status": "error", "message": "Failed to start frida scripts"}), 500

@app.route('/start-frida-satellite', methods=['POST'])
def start_frida_satellite_endpoint():
    print("\n=== Received: /start-frida-satellite ===")

    success = start_frida_satellite()
    if success:
        return jsonify({"status": "ok", "message": "Frida satellite script started"}), 200
    else:
        return jsonify({"status": "error", "message": "Failed to start frida satellite script"}), 500



@app.route('/wait-for-block', methods=['POST'])
def wait_for_block():
    """
    Wait for any Frida blocker script to report a blocked call.
    Returns as soon as "BLOCKED:" is seen in any Frida process output.
    Timeout: 30 seconds (configurable via JSON body)
    """
    print("\n=== Received: /wait-for-block ===")
    
    data = request.get_json() or {}
    timeout_s = data.get('timeout', 30.0)  # Default 30 seconds
    
    if not frida_processes:
        print("No Frida processes running")
        return jsonify({"status": "error", "message": "No Frida processes running", "blocked": False}), 500
    
    end_time = time.monotonic() + timeout_s
    print(f"Waiting for BLOCKED marker (timeout: {timeout_s}s)...")
    
    # Buffer for each process to accumulate partial reads
    proc_buffers = {id(proc): b"" for proc in frida_processes}
    
    while time.monotonic() < end_time:
        for proc in frida_processes:
            if proc.stdout is None:
                continue
            if proc.poll() is not None:
                continue  # Process dead
            
            fd = proc.stdout.fileno()
            
            # Non-blocking read with short timeout
            try:
                rlist, _, _ = select.select([fd], [], [], 0.1)
            except (ValueError, OSError):
                # fd might be closed or invalid
                continue
                
            if rlist:
                try:
                    # Use os.read() for non-blocking fd (readline() doesn't work well with non-blocking)
                    chunk = os.read(fd, 4096)
                    if not chunk:
                        continue
                    
                    # Accumulate in buffer
                    proc_buffers[id(proc)] += chunk
                    
                    # Check if buffer contains BLOCKED marker
                    buf_str = proc_buffers[id(proc)].decode('utf-8', errors='replace')
                    if "BLOCKED:" in buf_str:
                        # Extract the line containing BLOCKED:
                        for line in buf_str.split('\n'):
                            if "BLOCKED:" in line:
                                print(f"*** CALL BLOCKED: {line.strip()}")
                                return jsonify({
                                    "status": "ok",
                                    "message": "Call blocked by Frida",
                                    "blocked": True,
                                    "detail": line.strip()
                                }), 200
                    
                    # Prevent unbounded growth - keep last 50KB
                    if len(proc_buffers[id(proc)]) > 50000:
                        proc_buffers[id(proc)] = proc_buffers[id(proc)][-25000:]
                        
                except BlockingIOError:
                    # No data available right now
                    continue
                except Exception as e:
                    # Log but don't crash - process might have closed
                    print(f"Error reading Frida output: {e}")
                    continue
        
        time.sleep(0.05)  # Small sleep to prevent CPU spin
    
    print("Timeout waiting for BLOCKED marker")
    return jsonify({
        "status": "timeout",
        "message": f"No block detected within {timeout_s}s",
        "blocked": False
    }), 200


@app.route('/pkill-phone', methods=['POST'])
def pkill_phone():
    print("\n=== Received: /pkill-phone ===")

    kill_frida_processes()

    # pkill com.android.phone
    print("Sending pkill command...")
    result = subprocess.run(
        ['adb', 'shell', 'su', '-c', 'pkill -f com.android.phone'],
        capture_output=True,
        text=True
    )
    print(f"pkill result: {result.returncode}")

    return jsonify({
        "status": "ok",
        "message": "Phone app killed"
    })


@app.route('/start-scat', methods=['POST'])
def start_scat_endpoint():
    print("\n=== Received: /start-scat ===")

    data = request.get_json() or {}
    modem_type = data.get('modem_type', 'qc')
    filename = data.get('filename', 'capture.pcap')

    if not filename.endswith('.pcap'):
        filename = filename.rsplit('.', 1)[0] + '.pcap'

    print(f"modem_type: {modem_type}, filename: {filename}")

    success, message = start_scat(modem_type, filename)
    if success:
        return jsonify({"status": "ok", "message": message}), 200
    else:
        return jsonify({"status": "error", "message": message}), 500


@app.route('/stop-scat', methods=['POST'])
def stop_scat_endpoint():
    """Stop scat recording."""
    print("\n=== Received: /stop-scat ===")

    stop_scat_process()

    return jsonify({
        "status": "ok",
        "message": "scat stopped"
    })


if __name__ == '__main__':
    print("=" * 50)
    print("Frida + SCAT Control Server")
    print("=" * 50)
    print(f"Script directory: {SCRIPT_DIR}")
    print(f"SCAT output directory: {SCAT_OUTPUT_DIR}")
    print("")
    print("Endpoints:")
    print("  POST /start-frida       - Start Frida scripts")
    print("  POST /pkill-phone       - Just pkill phone (no restart)")
    print("  POST /start-scat        - Start scat recording")
    print("                            Body: {modem_type, filename}")
    print("  POST /stop-scat         - Stop scat recording")
    print("")
    print("Remember to run: adb reverse tcp:5555 tcp:5555")
    print("=" * 50)

    app.run(host='0.0.0.0', port=5555, debug=False, threaded=True)
