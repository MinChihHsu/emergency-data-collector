#!/usr/bin/env python3
"""
run on Mac/Ubuntu

1. pip install flask
2. sudo python frida_server.py (sudo for scat)
3. adb reverse tcp:5555 tcp:5555
4. adb run frida-server on cellphone (for now)

* check the DIR of scripts first
* TODO: revise to python arguments
"""

from flask import Flask, jsonify, request
import subprocess
import os
import signal
import time
import re

app = Flask(__name__)

SCRIPT_DIR = "/Users/minchihhsu/Downloads/app"
GSM_DIAL_SCRIPT = os.path.join(SCRIPT_DIR, "s21_void_gsm_dial.js")
USERAGENT_SCRIPT = os.path.join(SCRIPT_DIR, "s21_void_useragent.js")

# Output directory for scat pcap files
SCAT_OUTPUT_DIR = "/Users/minchihhsu/Downloads/scat_output"

# USB Vendor IDs for different modem types
USB_VENDOR_IDS = {
    "qc": "05c6",      # Qualcomm
    "sec": "04e8",     # Samsung (Exynos)
    "mtk": "0e8d",     # MediaTek
}

frida_processes = []
scat_process = None


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


def start_frida_scripts():
    global frida_processes
    
    kill_frida_processes()
    time.sleep(0.5)
    
    devnull = subprocess.DEVNULL
    
    # gsm_dial
    try:
        proc1 = subprocess.Popen(
            ['frida', '-U', '-n', 'com.android.phone', '-l', GSM_DIAL_SCRIPT],
            stdout=devnull,
            stderr=devnull
        )
        frida_processes.append(proc1)
        print(f"Started frida for com.android.phone (PID: {proc1.pid})")
    except Exception as e:
        print(f"Error starting gsm_dial script: {e}")
        return False
    
    time.sleep(1)
    
    # useragent
    try:
        proc2 = subprocess.Popen(
            ['frida', '-U', '-n', 'com.sec.imsservice', '-l', USERAGENT_SCRIPT],
            stdout=devnull,
            stderr=devnull
        )
        frida_processes.append(proc2)
        print(f"Started frida for com.sec.imsservice (PID: {proc2.pid})")
    except Exception as e:
        print(f"Error starting useragent script: {e}")
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
    Command: sudo scat -t <modem> -u -a <port> -i 0 -F <filename>
    """
    global scat_process
    
    # Stop existing scat if running
    stop_scat_process()
    
    # Find USB port
    usb_port = find_usb_port(modem_type)
    if not usb_port:
        return False, "USB port not found"
    
    # Ensure output directory exists
    os.makedirs(SCAT_OUTPUT_DIR, exist_ok=True)
    
    # Build full path for output file
    output_file = os.path.join(SCAT_OUTPUT_DIR, filename)
    
    # Build scat command
    # Note: Using sudo, make sure sudoers is configured for passwordless scat
    cmd = ['sudo', 'scat', '-t', modem_type, '-u', '-a', usb_port, '-i', '0', '-F', output_file]
    print(f"Starting scat: {' '.join(cmd)}")
    
    try:
        scat_process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )
        print(f"scat started (PID: {scat_process.pid})")
        return True, f"scat started, output: {output_file}"
    except Exception as e:
        print(f"Error starting scat: {e}")
        return False, str(e)


def stop_scat_process():
    """Stop scat process by sending SIGINT (Ctrl+C)"""
    global scat_process
    
    if scat_process is not None:
        try:
            # Send SIGINT (equivalent to Ctrl+C)
            scat_process.send_signal(signal.SIGINT)
            scat_process.wait(timeout=5)
            print(f"scat stopped (PID: {scat_process.pid})")
        except subprocess.TimeoutExpired:
            scat_process.kill()
            print("scat killed (timeout)")
        except Exception as e:
            print(f"Error stopping scat: {e}")
        finally:
            scat_process = None
    
    # Also try to kill any orphan scat processes
    subprocess.run(['sudo', 'pkill', '-INT', 'scat'], capture_output=True)


@app.route('/start-frida', methods=['POST'])
def start_frida():
    print("\n=== Received: /start-frida ===")
    success = start_frida_scripts()
    return jsonify({
        "status": "ok" if success else "error",
        "message": "Frida scripts started" if success else "Failed to start"
    })


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
    """
    Start scat recording.
    Expected JSON body: { "modem_type": "qc", "filename": "test.pcap" }
    """
    print("\n=== Received: /start-scat ===")
    
    data = request.get_json() or {}
    modem_type = data.get('modem_type', 'qc')  # Default to Qualcomm
    filename = data.get('filename', 'capture.pcap')
    
    # Ensure filename ends with .pcap
    if not filename.endswith('.pcap'):
        filename = filename.rsplit('.', 1)[0] + '.pcap'
    
    print(f"modem_type: {modem_type}, filename: {filename}")
    
    success, message = start_scat(modem_type, filename)
    
    return jsonify({
        "status": "ok" if success else "error",
        "message": message
    })


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
