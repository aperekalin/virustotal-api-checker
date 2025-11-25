# Threat Intel API Checker

### (VirusTotal + First Watch Integration)

This tool processes a CSV of domains/URLs and enriches each row with threat-intelligence data from **VirusTotal** and **First Watch**.
It runs locally, requires no cloud components, and stores all credentials in a local `config.toml`.

> **Important:**
> `config.toml` is **NOT** included in the Git repository.
> Instead, you will find a file named **`MODIFY-THIS-config.toml`** — copy or rename this to `config.toml` and fill in your API credentials.

---

## ✨ Features

### 🔍 VirusTotal Integration

* Submits each domain/URL for URL scanning using the v3 API.
* Waits **15 seconds** after submitting (configurable).
* Fetches analysis results using the returned analysis ID.
* Extracts and writes `malicious + suspicious` detections into **Column 2** (`Number of Virus Total Detects`).

### 🛰️ First Watch Integration

* Authenticates using JWT via `/api/login`.
* Queries the domain lookup endpoint `/api/feed/check/{domain}`.
* Writes lookup results into:

  * **Column 3** → `First Watch` → `"1"` if a record exists, `"0"` otherwise
  * **Column 4** → `First Watch Details` → JSON response string
* Prints to console whether First Watch returned data for each domain.

### 🧹 Intelligent Input Cleaning

* Handles defanged domains:

  * `hxxp://example[.]com`
  * `domain[dot]com`
  * `domain;;;;;;`
* Converts bare domains into valid URLs for VirusTotal.
* Supports punycode (IDNA) domains.

### 🛡️ Robust & Safe

* Retries VirusTotal operations with exponential backoff.
* Automatically re-authenticates to First Watch if JWT expires.
* Invalid URLs are skipped gracefully (marked `"invalid_url"`).
* Only **one 15-second wait per row** (after submitting to VirusTotal).

---

## 🗂️ CSV Columns (Auto-Enforced)

The script ensures the header row always contains:

| Column | Header Name                       |
| ------ | --------------------------------- |
| 1      | **Domain Name**                   |
| 2      | **Number of Virus Total Detects** |
| 3      | **First Watch**                   |
| 4      | **First Watch Details**           |

---

## 🗂️ CSV Example

### Input

| domain            |
| ----------------- |
| example.com       |
| suspicious[.]site |
| hxxp://bad[.]io   |

### Output

| Domain Name     | Number of Virus Total Detects | First Watch | First Watch Details |
| --------------- | ----------------------------- | ----------- | ------------------- |
| example.com     | 0                             | 1           | `{...JSON...}`      |
| suspicious.site | 3                             | 0           |                     |
| bad.io          | 12                            | 1           | `{...JSON...}`      |

---

## 📦 Files Included

```
.
├── vt_checker.py
├── MODIFY-THIS-config.toml   ← template config
├── run_vt_checker.sh
├── requirements.txt
└── README.md
```

> Again, `config.toml` is **intentionally not included** in the repo.
> Copy/rename `MODIFY-THIS-config.toml` → `config.toml`.

---

## ⚙️ Installation

### 1. Create a virtual environment

```bash
python3 -m venv .venv
source .venv/bin/activate
```

### 2. Install dependencies

```bash
pip install -r requirements.txt
```

---

## 🔐 Configuration

Create a **`config.toml`** file by copying the included example:

```bash
cp MODIFY-THIS-config.toml config.toml
```

Then edit the file with your API credentials.

### VirusTotal API

```toml
[virustotal]
api_key = "YOUR_VIRUSTOTAL_API_KEY"
```

### First Watch API

```toml
[firstwatch]
base_url = "http://firstwatch.yatic.io"
username = "YOUR_FIRSTWATCH_USERNAME"
password = "YOUR_FIRSTWATCH_PASSWORD"
```

### Runtime Settings

```toml
[run]
sleep_seconds = 15
```

---

## ▶️ Running the Tool

### Using the launcher script

```bash
./run_vt_checker.sh input.csv
```

### Or manually

```bash
python vt_checker.py input.csv
```

The script updates the **same CSV** (atomic write via temp file).

---

## 🧠 How It Works

### 1. Normalize Input

* Refang (`hxxp`, `[.]`, etc.)
* Remove trailing junk
* Convert domains to URLs
* Extract hostname for First Watch

### 2. VirusTotal Workflow

1. Submit URL
2. Wait **15 seconds**
3. Fetch analysis
4. Write result to Column 2

### 3. First Watch Workflow

1. Authenticate using JWT
2. Lookup domain
3. Write:

   * `"1"` if domain exists
   * `"0"` if not
   * JSON details if found
4. Print result status to console

### 4. Save CSV

* Updates header automatically
* Writes file safely

---

## 🛠 Troubleshooting

### “Unable to canonicalize URL”

Input is malformed — tool will mark the row `"invalid_url"`.

### First Watch returns 401 Unauthorized

The tool automatically re-logins and retries.

### VirusTotal returns 429 Too Many Requests

Increase `sleep_seconds` in the config.

### JSON is too long for CSV editors

Use a viewer that supports long cells (VS Code recommended).

---

## 📜 License

MIT License — free for modification and commercial use.