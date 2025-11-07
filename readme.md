Threat Intel API Checker

A simple local Python tool that checks a list of domains or URLs against the VirusTotal API
.
For each domain in a CSV file, it submits a URL scan request, waits 15 seconds, retrieves the analysis results, and records the total number of malicious + suspicious detections back into the same CSV.

✨ Features

Uses the VirusTotal v3 API to scan URLs.

Reads a CSV file where the first column contains domains or URLs.

Submits each URL to VirusTotal, waits 15 seconds, fetches the analysis results, and adds the total detection count to the second column.

Respects rate limits (basic retry logic included).

Configurable via a simple config.toml file.

🧱 Project Structure
.
├── vt_checker.py         # Main script
├── config.toml           # Configuration file (API key, delay)
├── requirements.txt      # Python dependencies
└── README.md             # This file

⚙️ Setup Instructions
1. Prerequisites

Python 3.9+

A VirusTotal API key

2. Install Dependencies

Create and activate a virtual environment (recommended):

python -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate


Then install dependencies:

pip install -r requirements.txt

3. Configure API Key

Create or edit config.toml:

[virustotal]
api_key = "YOUR_VIRUSTOTAL_API_KEY"

[run]
sleep_seconds = 15


The sleep_seconds value controls how long the script waits between API calls.

🧩 Usage
Input CSV format
domain	score
example.com	
malicious-site.com	

The first column contains domains or URLs.

The first row is treated as a header (left unchanged).

The second column will be filled with the total of malicious + suspicious detections.

Run the tool
python vt_checker.py input.csv


or specify a custom config:

python vt_checker.py input.csv --config myconfig.toml

Output

After processing, the script updates the same CSV file in place.
For example:

domain	score
example.com	0
malicious-site.com	7
🧠 How It Works

Submit URL scan → POST /api/v3/urls

Wait 15 seconds

Retrieve analysis → GET /api/v3/analyses/{analysis_id}

Extract results → sum of malicious + suspicious

Write to CSV → store result in the second column

Wait 15 seconds before next entry

⚠️ Notes

The default delay (15 seconds) helps avoid hitting VirusTotal’s rate limits.
If you use a premium API key, you can lower it in config.toml.

If VirusTotal returns HTTP 429 (“rate limit exceeded”), the script retries automatically.

If the domain isn’t a full URL, the script prepends http:// before submitting it.

🧾 Example Run
$ python vt_checker.py test_domains.csv

[1/3] Submitting: http://example.com
Waiting 15s after submit...
Analysis status=completed, malicious=0, suspicious=0 -> total=0
Waiting 15s before moving to next row...
...
Done. Updated file: test_domains.csv

📜 License

This project is provided “as is” under the MIT License.
You are responsible for complying with VirusTotal’s API Terms of Service.