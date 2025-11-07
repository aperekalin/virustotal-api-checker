#!/usr/bin/env bash
set -e

# ============================
# Threat Intel API Checker Runner
# ============================

# Colors for better output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${GREEN}=== Threat Intel API Checker ===${NC}"

# 1. Ensure Python is installed
if ! command -v python3 &>/dev/null; then
    echo -e "${YELLOW}Python3 not found. Please install Python 3.9+ and re-run this script.${NC}"
    exit 1
fi

# 2. Create virtual environment if missing
if [ ! -d ".venv" ]; then
    echo -e "${GREEN}Creating virtual environment...${NC}"
    python3 -m venv .venv
fi

# 3. Activate virtual environment
echo -e "${GREEN}Activating virtual environment...${NC}"
source .venv/bin/activate

# 4. Install dependencies
echo -e "${GREEN}Installing dependencies...${NC}"
pip install -r requirements.txt

# 5. Ensure config.toml exists
CONFIG_FILE="config.toml"
if [ ! -f "$CONFIG_FILE" ]; then
    echo -e "${YELLOW}Config file not found. Creating a new one...${NC}"
    read -p "Enter your VirusTotal API key: " VT_API_KEY

    cat > "$CONFIG_FILE" <<EOF
[virustotal]
api_key = "$VT_API_KEY"

[run]
sleep_seconds = 15
EOF

    echo -e "${GREEN}Config file created at $CONFIG_FILE${NC}"
fi

# 6. Get CSV file argument
if [ -z "$1" ]; then
    echo -e "${YELLOW}Usage: ./run_vt_checker.sh <path_to_csv>${NC}"
    deactivate
    exit 1
fi

CSV_PATH="$1"

# 7. Run the checker
echo -e "${GREEN}Running vt_checker.py on ${CSV_PATH}...${NC}"
python vt_checker.py "$CSV_PATH"

# 8. Deactivate environment
deactivate

echo -e "${GREEN}Done! CSV updated successfully.${NC}"
