"""
Run this to verify all sources are reachable and returning data.
Uses Google's official test phishing URL — safe to scan.

Usage:
    python test_sources.py
"""

import sys
import cache
from analyzer.url_checker import (
    vt_scan, urlscan_scan, google_safe_browsing,
    phishtank_check, openphish_check, abuseipdb_check,
    unshorten_url, is_shortener,
)

# Google's official test URL — designed to trigger Safe Browsing detections safely
TEST_URL = "http://testsafebrowsing.appspot.com/s/phishing.html"
# Also test a shortener
TEST_SHORT = "https://bit.ly/3example"

PASS = "✅"
FAIL = "❌"
SKIP = "⏭️"


def check(label: str, result: dict, key_to_show: str = None):
    if result is None:
        print(f"  {FAIL} {label}: None returned")
        return
    if not result.get("available", True):
        print(f"  {SKIP} {label}: לא זמין (ללא מפתח API)")
        return
    if "error" in result:
        print(f"  {FAIL} {label}: שגיאה — {result['error']}")
        return
    val = result.get(key_to_show) if key_to_show else result
    print(f"  {PASS} {label}: {val if key_to_show else 'תגובה התקבלה'}")
    print(f"       תוצאה מלאה: {result}")


def main():
    cache.init_db()
    print(f"\n{'='*55}")
    print(f"  Veri — בדיקת מקורות")
    print(f"  URL לבדיקה: {TEST_URL}")
    print(f"{'='*55}\n")

    print("1. VirusTotal")
    try:
        r = vt_scan(TEST_URL)
        check("VirusTotal", r, "malicious")
    except Exception as e:
        print(f"  {FAIL} שגיאה: {e}")

    print("\n2. URLScan.io")
    try:
        r = urlscan_scan(TEST_URL)
        check("URLScan", r, "final_url")
    except Exception as e:
        print(f"  {FAIL} שגיאה: {e}")

    print("\n3. Google Safe Browsing")
    try:
        r = google_safe_browsing(TEST_URL)
        check("Google Safe Browsing", r, "threat_found")
    except Exception as e:
        print(f"  {FAIL} שגיאה: {e}")

    print("\n4. PhishTank")
    try:
        r = phishtank_check(TEST_URL)
        check("PhishTank", r, "in_database")
    except Exception as e:
        print(f"  {FAIL} שגיאה: {e}")

    print("\n5. OpenPhish")
    try:
        r = openphish_check(TEST_URL)
        check("OpenPhish", r, "threat_found")
    except Exception as e:
        print(f"  {FAIL} שגיאה: {e}")

    print("\n6. AbuseIPDB")
    try:
        r = abuseipdb_check(TEST_URL)
        check("AbuseIPDB", r, "abuse_score")
    except Exception as e:
        print(f"  {FAIL} שגיאה: {e}")

    print("\n7. URL Unshortening")
    try:
        final = unshorten_url("https://t.co/4jLPOtjKtJ")
        short = is_shortener("https://t.co/4jLPOtjKtJ")
        print(f"  {PASS} קישור מקוצר: {short}")
        print(f"  {PASS} יעד סופי: {final}")
    except Exception as e:
        print(f"  {FAIL} שגיאה: {e}")

    print(f"\n{'='*55}")
    print("  הבדיקה הסתיימה")
    print(f"{'='*55}\n")


if __name__ == "__main__":
    main()
