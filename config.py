import os
from dotenv import load_dotenv

load_dotenv()

TELEGRAM_TOKEN = os.getenv("TELEGRAM_TOKEN")
VIRUSTOTAL_KEY = os.getenv("VIRUSTOTAL_KEY")
ANTHROPIC_KEY = os.getenv("ANTHROPIC_KEY")
URLSCAN_KEY = os.getenv("URLSCAN_KEY")
GOOGLE_SAFE_BROWSING_KEY = os.getenv("GOOGLE_SAFE_BROWSING_KEY")
PHISHTANK_KEY = os.getenv("PHISHTANK_KEY")
ABUSEIPDB_KEY = os.getenv("ABUSEIPDB_KEY")
