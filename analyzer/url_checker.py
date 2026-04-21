import base64
import re
import time
import httpx
from config import VIRUSTOTAL_KEY, URLSCAN_KEY, GOOGLE_SAFE_BROWSING_KEY, PHISHTANK_KEY, ABUSEIPDB_KEY
import cache

VT_BASE       = "https://www.virustotal.com/api/v3"
US_BASE       = "https://urlscan.io/api/v1"
GSB_BASE      = "https://safebrowsing.googleapis.com/v4/threatMatches:find"
PHISHTANK_BASE = "https://checkurl.phishtank.com/checkurl/"
OPENPHISH_FEED = "https://openphish.com/feed.txt"
ABUSEIPDB_BASE = "https://api.abuseipdb.com/api/v2/check"

SHORTENERS = {
    "t.co", "bit.ly", "goo.gl", "tinyurl.com", "ow.ly", "buff.ly",
    "shorturl.at", "is.gd", "rb.gy", "cutt.ly", "tiny.cc", "bl.ink",
    "rebrand.ly", "short.io", "link.me",
}


def is_shortener(url: str) -> bool:
    try:
        domain = url.split("/")[2].lower().lstrip("www.")
        return domain in SHORTENERS
    except Exception:
        return False


def unshorten_url(url: str) -> str:
    try:
        r = httpx.head(url, follow_redirects=True, timeout=10)
        final = str(r.url)
        return final if final != url else url
    except Exception:
        try:
            r = httpx.get(url, follow_redirects=True, timeout=10)
            return str(r.url)
        except Exception:
            return url


def _extract_domain(url: str) -> str:
    m = re.search(r"(?:https?://)?([^/?\s]+)", url)
    return m.group(1).lower() if m else url.lower()


def _vt_headers():
    return {"x-apikey": VIRUSTOTAL_KEY}


def vt_scan(url: str) -> dict:
    cached = cache.get(f"vt:{url}")
    if cached:
        return cached

    url_id = base64.urlsafe_b64encode(url.encode()).rstrip(b"=").decode()
    r = httpx.get(f"{VT_BASE}/urls/{url_id}", headers=_vt_headers(), timeout=15)

    if r.status_code == 404:
        sub = httpx.post(f"{VT_BASE}/urls", headers=_vt_headers(), data={"url": url}, timeout=15)
        analysis_id = sub.json()["data"]["id"]
        time.sleep(15)
        r = httpx.get(f"{VT_BASE}/analyses/{analysis_id}", headers=_vt_headers(), timeout=15)
        stats = r.json()["data"]["attributes"]["stats"]
    else:
        stats = r.json()["data"]["attributes"]["last_analysis_stats"]

    result = {
        "malicious": stats.get("malicious", 0),
        "suspicious": stats.get("suspicious", 0),
        "harmless": stats.get("harmless", 0),
        "undetected": stats.get("undetected", 0),
    }
    cache.set(f"vt:{url}", result)
    return result


def urlscan_scan(url: str) -> dict:
    cached = cache.get(f"us:{url}")
    if cached:
        return cached

    headers = {"API-Key": URLSCAN_KEY, "Content-Type": "application/json"}
    sub = httpx.post(f"{US_BASE}/scan/", headers=headers, json={"url": url, "visibility": "unlisted"}, timeout=15)

    if sub.status_code not in (200, 201):
        return {"error": sub.text}

    scan_id = sub.json()["uuid"]
    time.sleep(10)

    for _ in range(6):
        res = httpx.get(f"{US_BASE}/result/{scan_id}/", timeout=15)
        if res.status_code == 200:
            data = res.json()
            result = {
                "final_url": data.get("page", {}).get("url", url),
                "malicious": data.get("verdicts", {}).get("overall", {}).get("malicious", False),
                "score": data.get("verdicts", {}).get("overall", {}).get("score", 0),
                "tags": data.get("verdicts", {}).get("overall", {}).get("tags", []),
            }
            cache.set(f"us:{url}", result)
            return result
        time.sleep(10)

    return {"error": "timeout waiting for urlscan result"}


def google_safe_browsing(url: str) -> dict:
    if not GOOGLE_SAFE_BROWSING_KEY:
        return {"available": False}

    cached = cache.get(f"gsb:{url}")
    if cached:
        return cached

    payload = {
        "client": {"clientId": "veri-bot", "clientVersion": "1.0"},
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}],
        },
    }
    try:
        r = httpx.post(f"{GSB_BASE}?key={GOOGLE_SAFE_BROWSING_KEY}", json=payload, timeout=10)
        data = r.json()
        matches = data.get("matches", [])
        result = {
            "available": True,
            "threat_found": bool(matches),
            "threat_types": [m.get("threatType") for m in matches],
        }
    except Exception as e:
        result = {"available": True, "threat_found": False, "error": str(e)}

    cache.set(f"gsb:{url}", result)
    return result


def phishtank_check(url: str) -> dict:
    if not PHISHTANK_KEY:
        return {"available": False}

    cached = cache.get(f"pt:{url}")
    if cached:
        return cached

    try:
        r = httpx.post(
            PHISHTANK_BASE,
            data={"url": url, "format": "json", "app_key": PHISHTANK_KEY},
            headers={"User-Agent": "phishtank/veri-bot"},
            timeout=10,
        )
        data = r.json()
        entry = data.get("results", {})
        result = {
            "available": True,
            "in_database": entry.get("in_database", False),
            "valid": entry.get("valid", False),
            "verified": entry.get("verified", False),
        }
    except Exception as e:
        result = {"available": True, "in_database": False, "error": str(e)}

    cache.set(f"pt:{url}", result)
    return result


def openphish_check(url: str) -> dict:
    cached = cache.get("openphish:feed")
    if cached:
        feed_urls = set(cached)
    else:
        try:
            r = httpx.get(OPENPHISH_FEED, timeout=15)
            feed_urls = set(line.strip() for line in r.text.splitlines() if line.strip())
            cache.set("openphish:feed", list(feed_urls), ttl=3600)
        except Exception as e:
            return {"available": False, "error": str(e)}

    # check exact match and domain match
    domain = _extract_domain(url)
    found = url in feed_urls or any(domain in u for u in feed_urls)
    return {"available": True, "threat_found": found}


def abuseipdb_check(url: str) -> dict:
    if not ABUSEIPDB_KEY:
        return {"available": False}

    domain = _extract_domain(url)
    cached = cache.get(f"abuse:{domain}")
    if cached:
        return cached

    try:
        r = httpx.get(
            ABUSEIPDB_BASE,
            params={"ipAddress": domain, "maxAgeInDays": 90, "verbose": ""},
            headers={"Key": ABUSEIPDB_KEY, "Accept": "application/json"},
            timeout=10,
        )
        data = r.json().get("data", {})
        result = {
            "available": True,
            "abuse_score": data.get("abuseConfidenceScore", 0),
            "total_reports": data.get("totalReports", 0),
            "domain": data.get("domain", domain),
            "is_whitelisted": data.get("isWhitelisted", False),
        }
    except Exception as e:
        result = {"available": True, "abuse_score": 0, "error": str(e)}

    cache.set(f"abuse:{domain}", result)
    return result
