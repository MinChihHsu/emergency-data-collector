#!/usr/bin/env python3
"""
upload_scat.py — Upload SCAT pcap files from scat_output/ to GCS.

Usage:
    python upload_scat.py

Requirements:
    pip install requests

Config:
    - Place gcs_service_account.json in the same directory (same key as the Android app)
    - Set GCS_BUCKET below to match your bucket name
    - Uploaded files are tracked in scat_upload_log.json (auto-created)
"""

import os
import json
import time
import base64
import hashlib
import re
import argparse
import requests
import urllib.parse

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

# ─────────────────────────────────────────────────────────────────────────────
# Edit these if needed:
GCS_BUCKET = "emergency-data-collector-logs"
_SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
SA_KEY_FILE     = os.path.join(_SCRIPT_DIR, "gcs_service_account.json")   # same key as Android app
UPLOAD_LOG_FILE = os.path.join(_SCRIPT_DIR, "scat_upload_log.json")       # auto-created
SCAT_DIR        = "scat_output"   # default, overridden by --dir arg
# ─────────────────────────────────────────────────────────────────────────────

GCS_TOKEN_URL = "https://oauth2.googleapis.com/token"
GCS_SCOPE = "https://www.googleapis.com/auth/devstorage.read_write"

_token_cache = {"token": None, "expiry": 0}


def get_gcs_token(sa_key_path: str) -> str:
    """Get OAuth2 bearer token from Service Account JSON key using JWT (no google-auth needed)."""
    if _token_cache["token"] and time.time() < _token_cache["expiry"]:
        return _token_cache["token"]

    with open(sa_key_path) as f:
        sa = json.load(f)

    client_email = sa["client_email"]
    private_key_pem = sa["private_key"].encode()

    now = int(time.time())
    header = base64.urlsafe_b64encode(json.dumps({"alg": "RS256", "typ": "JWT"}).encode()).rstrip(b"=")
    claims = base64.urlsafe_b64encode(json.dumps({
        "iss": client_email,
        "scope": GCS_SCOPE,
        "aud": GCS_TOKEN_URL,
        "iat": now,
        "exp": now + 3600
    }).encode()).rstrip(b"=")

    jwt_unsigned = header + b"." + claims

    # Sign using cryptography library
    private_key = serialization.load_pem_private_key(private_key_pem, password=None)
    signature = private_key.sign(jwt_unsigned, padding.PKCS1v15(), hashes.SHA256())
    sig_b64 = base64.urlsafe_b64encode(signature).rstrip(b"=")

    jwt = jwt_unsigned + b"." + sig_b64

    resp = requests.post(GCS_TOKEN_URL, data={
        "grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer",
        "assertion": jwt.decode()
    }, timeout=15)
    resp.raise_for_status()

    token = resp.json()["access_token"]
    _token_cache["token"] = token
    _token_cache["expiry"] = now + 3500   # cache ~58 min
    return token


def md5_base64(filepath: str) -> str:
    """Compute MD5 of a file and return as Base64 (for Content-MD5 header)."""
    md5 = hashlib.md5()
    with open(filepath, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            md5.update(chunk)
    return base64.b64encode(md5.digest()).decode()


def parse_folder_name(filename: str) -> str:
    """
    Folder = everything from filename start up to (and including) the date token.
    e.g. TW_Chunghwa_Pixel_10_6770fca51d658278_20260223
    Date is identified as the first 8-digit all-numeric token (yyyyMMdd).
    """
    stem = os.path.splitext(filename)[0]
    parts = stem.split("_")

    date_idx = next((i for i, p in enumerate(parts) if re.match(r'^\d{8}$', p)), None)

    if date_idx is None or date_idx < 1:
        return stem   # fallback: filename stem as folder

    return "_".join(parts[:date_idx + 1])


def upload_file(filepath: str, token: str) -> bool:
    """Upload a single file to GCS with Content-MD5 integrity check."""
    filename = os.path.basename(filepath)
    folder = parse_folder_name(filename)
    object_name = urllib.parse.quote(f"{folder}/{filename}", safe="")
    upload_url = (
        f"https://storage.googleapis.com/upload/storage/v1/b/{GCS_BUCKET}/o"
        f"?uploadType=media&name={object_name}"
    )

    md5 = md5_base64(filepath)
    file_size = os.path.getsize(filepath)

    print(f"  Uploading: {filename} ({file_size / 1024:.1f} KB) → {folder}/")

    with open(filepath, "rb") as f:
        resp = requests.post(
            upload_url,
            data=f,
            headers={
                "Authorization": f"Bearer {token}",
                "Content-Type": "application/octet-stream",
                "Content-MD5": md5,
                "Content-Length": str(file_size),
            },
            timeout=120,
            stream=False
        )

    if resp.status_code in (200, 201):
        print(f"  ✅ OK (MD5 verified by GCS)")
        return True
    else:
        print(f"  ❌ Failed ({resp.status_code}): {resp.text[:200]}")
        return False


def load_upload_log() -> set:
    if os.path.exists(UPLOAD_LOG_FILE):
        with open(UPLOAD_LOG_FILE) as f:
            return set(json.load(f).get("uploaded", []))
    return set()


def save_upload_log(uploaded: set):
    with open(UPLOAD_LOG_FILE, "w") as f:
        json.dump({"uploaded": sorted(uploaded)}, f, indent=2)


def main():
    parser = argparse.ArgumentParser(
        description="Upload SCAT pcap files to GCS.",
        usage="python upload_scat.py --dir /path/to/scat_output"
    )
    parser.add_argument(
        "--dir", default="scat_output",
        metavar="DIR",
        help="Directory containing SCAT .pcap files (default: scat_output)"
    )
    args = parser.parse_args()

    global SCAT_DIR
    SCAT_DIR = args.dir

    print("=" * 55)
    print("SCAT → GCS Uploader")
    print("=" * 55)
    print(f"  SCAT dir : {SCAT_DIR}")
    print(f"  Bucket   : {GCS_BUCKET}")
    print()

    # Validate config
    if not os.path.exists(SA_KEY_FILE):
        print(f"❌ Service account key not found: {SA_KEY_FILE}")
        return
    if not os.path.isdir(SCAT_DIR):
        print(f"❌ SCAT output directory not found: {SCAT_DIR}/")
        return

    # Discover .pcap files
    all_files = [
        f for f in os.listdir(SCAT_DIR)
        if f.endswith(".pcap") and os.path.isfile(os.path.join(SCAT_DIR, f))
    ]

    uploaded = load_upload_log()
    to_upload = [f for f in all_files if f not in uploaded]

    print(f"Found {len(all_files)} pcap file(s), {len(to_upload)} need uploading")

    if not to_upload:
        print("✅ Nothing to upload — all files already uploaded")
        return

    # Get token once (reused for all files)
    print("\nAuthenticating with GCS...")
    try:
        token = get_gcs_token(SA_KEY_FILE)
        print("✅ Token acquired\n")
    except Exception as e:
        print(f"❌ Auth failed: {e}")
        return

    success, failed = 0, 0
    for i, filename in enumerate(to_upload, 1):
        print(f"[{i}/{len(to_upload)}] {filename}")
        filepath = os.path.join(SCAT_DIR, filename)
        try:
            ok = upload_file(filepath, token)
        except Exception as e:
            print(f"  ❌ Exception: {e}")
            ok = False

        if ok:
            success += 1
            uploaded.add(filename)
            save_upload_log(uploaded)   # persist after each file
        else:
            failed += 1
        print()

    print("=" * 55)
    print(f"Done: {success} uploaded, {failed} failed")
    print("=" * 55)


if __name__ == "__main__":
    main()
