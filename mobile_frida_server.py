#!/usr/bin/env python3
"""
run on phone

1. pip install flask
2. frida-server in /data/local/tmp/
3. scripts in /data/local/tmp/
4. python mobile_frida_server.py
"""

from flask import Flask, jsonify, request
import subprocess
import os
import time

app = Flask(__name__)

# your own config
SCRIPT_DIR = "/data/local/tmp"
FRIDA_SERVER = os.path.join(SCRIPT_DIR, "frida-server-17.5.2-android-arm64")
GSM_DIAL_SCRIPT = os.path.join(SCRIPT_DIR, "s21_void_gsm_dial.js")
USERAGENT_SCRIPT = os.path.join(SCRIPT_DIR, "s21_void_useragent.js")

frida_processes = []

# still some problem, this one cannot start frida-server itself
# so I still need to execute it manually
def ensure_frida_server_running():
    result = subprocess.run(
        ['pgrep', '-f', 'frida-server'],
        capture_output=True,
        text=True
    )
    
    if result.returncode != 0:
        # if not, start it
        print("Starting frida-server...")
        subprocess.Popen(
            ['su', '-c', f'{FRIDA_SERVER} -D &'],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            shell=False
        )
        time.sleep(2)
        print("frida-server started")
    else:
        print(f"frida-server already running (PID: {result.stdout.strip()})")


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
    
    subprocess.run(['pkill', '-f', 'frida -H'], capture_output=True)


def start_frida_scripts():
    global frida_processes
    
    ensure_frida_server_running()
    
    kill_frida_processes()
    time.sleep(0.5)

    devnull = subprocess.DEVNULL
    
    # gsm_dial
    if os.path.exists(GSM_DIAL_SCRIPT):
        try:
            proc1 = subprocess.Popen(
                ['frida', '-H', '127.0.0.1', '-n', 'com.android.phone', '-l', GSM_DIAL_SCRIPT],
                stdout=devnull,
                stderr=devnull
            )
            frida_processes.append(proc1)
            print(f"Started frida for com.android.phone (PID: {proc1.pid})")
        except Exception as e:
            print(f"Error starting gsm_dial script: {e}")
    else:
        print(f"GSM script not found: {GSM_DIAL_SCRIPT}")
    
    time.sleep(1)
    
    # useragent
    if os.path.exists(USERAGENT_SCRIPT):
        try:
            proc2 = subprocess.Popen(
                ['frida', '-H', '127.0.0.1', '-n', 'com.sec.imsservice', '-l', USERAGENT_SCRIPT],
                stdout=devnull,
                stderr=devnull
            )
            frida_processes.append(proc2)
            print(f"Started frida for com.sec.imsservice (PID: {proc2.pid})")
        except Exception as e:
            print(f"Error starting useragent script: {e}")
    else:
        print(f"Useragent script not found: {USERAGENT_SCRIPT}")
    
    return len(frida_processes) > 0


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
        ['su', '-c', 'pkill -f com.android.phone'],
        capture_output=True,
        text=True
    )
    print(f"pkill result: {result.returncode}")
    
    return jsonify({
        "status": "ok",
        "message": "Phone app killed"
    })


if __name__ == '__main__':
    print("=" * 50)
    print("Mobile Frida Control Server (Termux)")
    print("=" * 50)
    print(f"Frida server: {FRIDA_SERVER}")
    print(f"GSM Dial script: {GSM_DIAL_SCRIPT}")
    print(f"Useragent script: {USERAGENT_SCRIPT}")
    print("")
    print("Endpoints:")
    print("  POST /start-frida       - Start Frida scripts")
    print("  POST /pkill-phone       - Just pkill phone (no restart)")
    print("")
    print("Listening on http://127.0.0.1:5555")
    print("=" * 50)
    
    ensure_frida_server_running()
    
    app.run(host='127.0.0.1', port=5555, debug=False, threaded=True)
