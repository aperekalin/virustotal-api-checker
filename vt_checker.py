#!/usr/bin/env python3
import csv
import os
import re
import time
import requests
from urllib.parse import urlsplit, urlunsplit
from requests.utils import requote_uri

# ---- config loading (tomllib for 3.11+, fallback to toml) ----
try:
    import tomllib  # py311+
    def load_toml(path):
        with open(path, "rb") as f:
            return tomllib.load(f)
except Exception:
    import toml
    def load_toml(path):
        with open(path, "r", encoding="utf-8") as f:
            return toml.load(f)

VT_SCAN_URL = "https://www.virustotal.com/api/v3/urls"
VT_ANALYSIS_URL = "https://www.virustotal.com/api/v3/analyses/{analysis_id}"

# ---------- Helpers ----------
def read_config(cfg_path: str = "config.toml"):
    if not os.path.exists(cfg_path):
        raise FileNotFoundError(f"Config file not found: {cfg_path}")
    cfg = load_toml(cfg_path)
    api_key = cfg.get("virustotal", {}).get("api_key")
    if not api_key:
        raise ValueError("Missing virustotal.api_key in config.toml")
    sleep_seconds = int(cfg.get("run", {}).get("sleep_seconds", 15))
    return api_key, sleep_seconds

def vt_headers(api_key: str):
    return {
        "x-apikey": api_key,
        "Accept": "application/json",
    }

def submit_url_for_scan(api_key: str, url: str):
    # POST form-encoded "url"
    resp = requests.post(
        VT_SCAN_URL,
        headers={**vt_headers(api_key), "Content-Type": "application/x-www-form-urlencoded"},
        data={"url": url},
        timeout=30,
    )
    if resp.status_code >= 400:
        try:
            err = resp.json()
        except Exception:
            err = resp.text
        raise RuntimeError(f"VT submit failed ({resp.status_code}): {err}")
    j = resp.json()
    return j["data"]["id"]

def fetch_analysis_stats(api_key: str, analysis_id: str):
    resp = requests.get(
        VT_ANALYSIS_URL.format(analysis_id=analysis_id),
        headers=vt_headers(api_key),
        timeout=30,
    )
    if resp.status_code >= 400:
        try:
            err = resp.json()
        except Exception:
            err = resp.text
        raise RuntimeError(f"VT analysis fetch failed ({resp.status_code}): {err}")
    j = resp.json()
    attrs = j.get("data", {}).get("attributes", {})
    stats = attrs.get("stats", {}) or {}
    malicious = int(stats.get("malicious", 0))
    suspicious = int(stats.get("suspicious", 0))
    return malicious, suspicious, attrs.get("status")

# ---- Input normalization (refang + clean + quote) ----
_SPLIT_ON = re.compile(r"[;\s,\|]+")
_SCHEME_RE = re.compile(r"^[a-zA-Z][a-zA-Z0-9+\-.]*://")

def normalize_url(raw: str) -> str:
    s = (raw or "").strip().strip('"').strip("'")
    if not s:
        raise ValueError("empty")

    # if a cell has "domain;;;;;;" or "domain,," keep first token
    s = _SPLIT_ON.split(s)[0]

    # refang common patterns
    refangs = [
        (r"\[\.]", "."),
        (r"\(\.\)", "."),
        (r"\[dot\]", "."),
        (r"hxxps://", "https://"),
        (r"hxxp://", "http://"),
        (r"^hxxps\b", "https"),
        (r"^hxxp\b", "http"),
        (r"\[:\/\/\]", "://"),
    ]
    for pat, repl in refangs:
        s = re.sub(pat, repl, s, flags=re.IGNORECASE)

    # strip trailing punctuation that breaks canonicalization
    s = re.sub(r"[;,\.\)]*$", "", s)

    # add scheme if missing
    if not _SCHEME_RE.match(s):
        s = "http://" + s

    parts = urlsplit(s)
    if not parts.netloc:
        raise ValueError(f"no host in URL: {s}")

    # separate userinfo and host:port
    userinfo_hostport = parts.netloc.rsplit("@", 1)
    userinfo = userinfo_hostport[0] if len(userinfo_hostport) == 2 else ""
    hostport = userinfo_hostport[-1]

    # split host/port
    if hostport.startswith("["):  # IPv6 like [2001:db8::1]:443
        host_end = hostport.find("]")
        host = hostport[:host_end+1]
        port = hostport[host_end+2:] if host_end != -1 and host_end+2 < len(hostport) else ""
    else:
        hp = hostport.split(":", 1)
        host, port = (hp[0], hp[1]) if len(hp) == 2 else (hp[0], "")

    # IDNA for non-IP hosts
    is_ipv6 = host.startswith("[") and host.endswith("]")
    is_ipv4 = re.match(r"^\d{1,3}(\.\d{1,3}){3}$", host) is not None
    if not is_ipv4 and not is_ipv6:
        try:
            host = host.encode("idna").decode("ascii")
        except Exception:
            pass

    netloc = (f"{userinfo}@" if userinfo else "") + host + (f":{port}" if port else "")

    # ensure a path at least
    path = parts.path or "/"
    rebuilt = urlunsplit((parts.scheme, netloc, path, parts.query, parts.fragment))
    return requote_uri(rebuilt)

# ---- CSV processing ----
def _read_rows_with_sniffer(csv_path: str):
    """Try to auto-detect delimiter; fall back to comma."""
    with open(csv_path, "r", newline="", encoding="utf-8") as f:
        sample = f.read(4096)
        f.seek(0)
        try:
            dialect = csv.Sniffer().sniff(sample, delimiters=",;|\t")
            reader = csv.reader(f, dialect)
        except Exception:
            reader = csv.reader(f)  # default comma
        return list(reader)

def process_csv(csv_path: str, api_key: str, sleep_seconds: int):
    if not os.path.exists(csv_path):
        raise FileNotFoundError(f"CSV not found: {csv_path}")

    rows = _read_rows_with_sniffer(csv_path)
    if not rows:
        print("Empty CSV; nothing to do.")
        return

    for i in range(1, len(rows)):  # skip header
        row = rows[i]
        if len(row) < 2:
            row += [""] * (2 - len(row))

        raw = row[0]
        if not raw or not raw.strip():
            row[1] = ""
            rows[i] = row
            continue

        try:
            url = normalize_url(raw)
        except Exception as e:
            row[1] = "invalid_url"
            print(f"[row {i+1}] Skipping invalid input '{raw}': {e}")
            rows[i] = row
            continue

        print(f"[{i}/{len(rows)-1}] Submitting: {url}")

        # Step 1: submit URL scan
        retries = 0
        while True:
            try:
                analysis_id = submit_url_for_scan(api_key, url)
                break
            except Exception as e:
                retries += 1
                if retries > 3:
                    raise
                wait = min(30, 5 * retries)
                print(f"Submit failed ({e}); retrying in {wait}s...")
                time.sleep(wait)

        print(f"Waiting {sleep_seconds}s after submit...")
        time.sleep(sleep_seconds)

        # Step 2: fetch analysis
        retries = 0
        while True:
            try:
                malicious, suspicious, status = fetch_analysis_stats(api_key, analysis_id)
                total = malicious + suspicious
                row[1] = str(total)
                print(f"Analysis status={status}, malicious={malicious}, suspicious={suspicious} -> total={total}")
                break
            except Exception as e:
                retries += 1
                if retries > 3:
                    raise
                wait = min(30, 5 * retries)
                print(f"Fetch failed ({e}); retrying in {wait}s...")
                time.sleep(wait)

        print(f"Waiting {sleep_seconds}s before moving to next row...")
        time.sleep(sleep_seconds)

        rows[i] = row

    # write back atomically
    tmp_path = csv_path + ".tmp"
    with open(tmp_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerows(rows)
    os.replace(tmp_path, csv_path)
    print(f"Done. Updated file: {csv_path}")

# ---- CLI ----
if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Threat Intel API Checker (VirusTotal URL scans)")
    parser.add_argument("csv", help="Path to input CSV. Column 1 must contain domains/URLs.")
    parser.add_argument("--config", default="config.toml", help="Path to config.toml (default: config.toml)")
    args = parser.parse_args()

    key, sleep_s = read_config(args.config)
    process_csv(args.csv, key, sleep_s)
