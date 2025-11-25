#!/usr/bin/env python3
import csv
import os
import re
import json
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

# ---------- Config ----------
def read_config(cfg_path: str = "config.toml"):
    if not os.path.exists(cfg_path):
        raise FileNotFoundError(f"Config file not found: {cfg_path}")
    cfg = load_toml(cfg_path)

    vt_api_key = cfg.get("virustotal", {}).get("api_key")
    if not vt_api_key:
        raise ValueError("Missing virustotal.api_key in config.toml")

    sleep_seconds = int(cfg.get("run", {}).get("sleep_seconds", 15))

    fw = cfg.get("firstwatch", {}) or {}
    fw_base = fw.get("base_url", "http://firstwatch.yatic.io").rstrip("/")
    fw_user = fw.get("username")
    fw_pass = fw.get("password")
    if not fw_user or not fw_pass:
        raise ValueError("Missing firstwatch.username or firstwatch.password in config.toml")

    return {
        "vt_api_key": vt_api_key,
        "sleep_seconds": sleep_seconds,
        "fw_base": fw_base,
        "fw_user": fw_user,
        "fw_pass": fw_pass,
    }

# ---------- VirusTotal helpers ----------
def vt_headers(api_key: str):
    return {"x-apikey": api_key, "Accept": "application/json"}

def submit_url_for_scan(api_key: str, url: str):
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

# ---------- First Watch helpers ----------
class FirstWatchClient:
    def __init__(self, base_url: str, username: str, password: str):
        self.base_url = base_url.rstrip("/")
        self.username = username
        self.password = password
        self._token = None
        self._session = requests.Session()

    def _login(self):
        url = f"{self.base_url}/api/login"
        resp = self._session.post(
            url,
            headers={"Content-Type": "application/x-www-form-urlencoded", "Accept": "application/json"},
            data={"username": self.username, "password": self.password},
            timeout=30,
        )
        resp.raise_for_status()
        data = resp.json()
        # try common token field names; adjust if your API uses a different key
        token = data.get("token") or data.get("access_token") or data.get("jwt") or data.get("data") or data.get("auth")
        if not token or not isinstance(token, str):
            # if the API returns raw JWT string, handle that too
            if isinstance(data, str) and len(data.split(".")) == 3:
                token = data
            else:
                raise RuntimeError(f"First Watch login: token not found in response: {data}")
        self._token = token

    def _authz(self):
        if not self._token:
            self._login()
        return {"Authorization": f"Bearer {self._token}", "Accept": "application/json"}

    def domain_lookup(self, domain: str):
        """Return (found: bool, json_or_none). If unauthorized, refresh token once."""
        url = f"{self.base_url}/api/feed/check/{domain}"
        hdrs = self._authz()
        resp = self._session.get(url, headers=hdrs, timeout=30)
        if resp.status_code == 401:
            # token expired; login once and retry
            self._login()
            hdrs = self._authz()
            resp = self._session.get(url, headers=hdrs, timeout=30)

        if resp.status_code == 404:
            return False, None

        # For other errors, raise; caller will catch/log and treat as not found
        if resp.status_code >= 400:
            raise RuntimeError(f"First Watch lookup failed ({resp.status_code}): {resp.text}")

        try:
            data = resp.json()
        except Exception:
            # if server returns non-JSON body but 200 OK, treat as not found
            return False, None

        # Consider "found" if domain_name present or non-empty JSON
        found = False
        if isinstance(data, dict):
            found = bool(data.get("domain_name") or data)  # non-empty dict
        elif isinstance(data, list):
            found = len(data) > 0

        return found, data if found else None

# ---- Input normalization (refang + clean + quote) ----
_SPLIT_ON = re.compile(r"[;\s,\|]+")
_SCHEME_RE = re.compile(r"^[a-zA-Z][a-zA-Z0-9+\-.]*://")

def normalize_url(raw: str) -> str:
    s = (raw or "").strip().strip('"').strip("'")
    if not s:
        raise ValueError("empty")
    s = _SPLIT_ON.split(s)[0]  # keep only first token if "domain;;;;" or "domain,foo"
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

    s = re.sub(r"[;,\.\)]*$", "", s)  # trailing punctuation

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
    path = parts.path or "/"
    rebuilt = urlunsplit((parts.scheme, netloc, path, parts.query, parts.fragment))
    return requote_uri(rebuilt)

def hostname_from_url(url: str) -> str:
    """Extract hostname from normalized URL for First Watch (strip brackets for IPv6)."""
    parts = urlsplit(url)
    host = parts.hostname or ""
    if host.startswith("[") and host.endswith("]"):
        host = host[1:-1]
    return host

# ---- CSV helpers ----
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

def _ensure_headers_and_width(rows):
    """Ensure columns:
       [0] = Domain Name
       [1] = Number of Virus Total Detects
       [2] = First Watch
       [3] = First Watch Details
    """
    if not rows:
        return [["Domain Name", "Number of Virus Total Detects", "First Watch", "First Watch Details"]]

    header = rows[0]

    # Ensure at least 4 columns
    while len(header) < 4:
        header.append("")

    # Force required header names
    header[0] = "Domain Name"
    header[1] = "Number of Virus Total Detects"
    if not header[2]:
        header[2] = "First Watch"
    if not header[3]:
        header[3] = "First Watch Details"

    rows[0] = header

    # Ensure each row has >= 4 columns
    for i in range(1, len(rows)):
        r = rows[i]
        if len(r) < 4:
            r += [""] * (4 - len(r))
        rows[i] = r

    return rows

# ---- Main processing ----
def process_csv(csv_path: str, vt_api_key: str, sleep_seconds: int, fw_client: FirstWatchClient):
    if not os.path.exists(csv_path):
        raise FileNotFoundError(f"CSV not found: {csv_path}")

    rows = _read_rows_with_sniffer(csv_path)
    rows = _ensure_headers_and_width(rows)
    if not rows or len(rows) == 1:
        print("No data rows; nothing to do.")
        return

    for i in range(1, len(rows)):  # skip header
        row = rows[i]
        raw = row[0]
        if not raw or not raw.strip():
            # leave cols 1..3 blank if no input
            rows[i] = row
            continue

        # --- Normalize to URL for VT ---
        try:
            url = normalize_url(raw)
        except Exception as e:
            row[1] = ""            # VT score
            row[2] = "0"           # First Watch
            row[3] = ""            # First Watch Details
            print(f"[row {i+1}] Skipping invalid input '{raw}': {e}")
            rows[i] = row
            continue

        # --- VIRUSTOTAL: submit -> wait -> fetch (kept exactly as before) ---
        print(f"[{i}/{len(rows)-1}] Submitting to VT: {url}")

        # Submit
        retries = 0
        while True:
            try:
                analysis_id = submit_url_for_scan(vt_api_key, url)
                break
            except Exception as e:
                retries += 1
                if retries > 3:
                    print(f"Giving up on VT submit for row {i+1}: {e}")
                    analysis_id = None
                    break
                wait = min(30, 5 * retries)
                print(f"Submit failed ({e}); retrying in {wait}s...")
                time.sleep(wait)

        # VT sleep #1 (per spec)
        print(f"Waiting {sleep_seconds}s after VT submit...")
        time.sleep(sleep_seconds)

        # Fetch analysis if we have an ID
        vt_total = ""
        if analysis_id:
            retries = 0
            while True:
                try:
                    malicious, suspicious, status = fetch_analysis_stats(vt_api_key, analysis_id)
                    vt_total = str(malicious + suspicious)
                    print(f"VT analysis status={status}, malicious={malicious}, suspicious={suspicious} -> total={vt_total}")
                    break
                except Exception as e:
                    retries += 1
                    if retries > 3:
                        print(f"Giving up on VT fetch for row {i+1}: {e}")
                        break
                    wait = min(30, 5 * retries)
                    print(f"Fetch failed ({e}); retrying in {wait}s...")
                    time.sleep(wait)

        row[1] = vt_total  # write VT score (can be "" if VT failed)

        # --- FIRST WATCH: domain lookup ---
        domain_for_fw = hostname_from_url(url)
        try:
            found, fw_json = fw_client.domain_lookup(domain_for_fw)
        except Exception as e:
            print(f"First Watch lookup error on '{domain_for_fw}': {e}")
            found, fw_json = False, None

        # Console logging (new)
        if found:
            print(f"First Watch: found data for '{domain_for_fw}'")
        else:
            print(f"First Watch: no record found for '{domain_for_fw}'")

        # Write to CSV

        row[2] = "1" if found else "0"
        row[3] = json.dumps(fw_json, ensure_ascii=False) if found else ""

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
    parser = argparse.ArgumentParser(description="Threat Intel API Checker (VirusTotal + First Watch)")
    parser.add_argument("csv", help="Path to input CSV. Column 1 must contain domains/URLs.")
    parser.add_argument("--config", default="config.toml", help="Path to config.toml (default: config.toml)")
    args = parser.parse_args()

    cfg = read_config(args.config)

    fw_client = FirstWatchClient(
        base_url=cfg["fw_base"],
        username=cfg["fw_user"],
        password=cfg["fw_pass"],
    )

    process_csv(
        csv_path=args.csv,
        vt_api_key=cfg["vt_api_key"],
        sleep_seconds=cfg["sleep_seconds"],
        fw_client=fw_client,
    )
