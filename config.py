"""
config.py

Configuration file for VTBulkScanner.
Store your VirusTotal API key here.
"""

# ==========================================
# VirusTotal API Key
# Get yours from:
# https://www.virustotal.com/gui/join-us
# ============================================

API_KEY = "YOUR_VIRUSTOTAL_API_KEY"

# VirusTotal API URL

BASE_URL = "https://www.virustotal.com/api/v3"

# Request timeout (seconds)

TIMEOUT = 30

# Output directory

OUTPUT_DIR = "output"

# Input file

INPUT_FILE = "input/urls.txt"

# User-Agent (optional)

USER_AGENT = "VTBulkScanner/1.0"
