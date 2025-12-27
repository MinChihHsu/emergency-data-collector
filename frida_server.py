#!/usr/bin/env python3
"""
run on Mac

1. pip install flask
2. python frida_server.py
3. adb reverse tcp:5000 tcp:5000
"""

from flask import Flask, jsonify, request
import subprocess
import os
import signal
import time

app = Flask(__name__)

SCRIPT_DIR = "/Users/minchihhsu/Downloads/app"
GSM_DIAL_SCRIPT = os.path.join(SCRIPT_DIR, "s21_void-gsm_dial.js")
USERAGENT_SCRIPT = os.path.join(SCRIPT_DIR, "s21_void_useragent.js")

frida_processes = []


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
        ['adb', 'shell', 'su', '-c', 'pkill com.android.phone'],
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
    print("Frida Control Server")
    print("=" * 50)
    print(f"Script directory: {SCRIPT_DIR}")
    print(f"GSM Dial script: {GSM_DIAL_SCRIPT}")
    print(f"Useragent script: {USERAGENT_SCRIPT}")
    print("")
    print("Endpoints:")
    print("  POST /start-frida       - Start Frida scripts")
    print("  POST /pkill-phone       - Just pkill phone (no restart)")
    print("")
    print("Remember to run: adb reverse tcp:5555 tcp:5555")
    print("=" * 50)
    
    app.run(host='0.0.0.0', port=5555, debug=False, threaded=True)
