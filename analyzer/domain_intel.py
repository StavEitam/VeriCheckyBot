import asyncio
import re
import whois
from datetime import datetime, timezone
from urllib.parse import unquote

BRANDS = [
    # בנקים וכרטיסי אשראי
    "paypal", "visa", "mastercard",
    "bankhapoalim", "bankleumi", "hapoalim", "leumi", "poalim",
    "mizrahi", "mizrahitefahot", "discount", "bankdiscount",
    "fibi", "otzar", "benleumi", "firstinternational",
    "isracard", "max", "cal", "bit", "pepper",

    # ביטוח
    "clal", "harel", "menora", "migdal", "phoenix",
    "directinsurance", "direct-insurance", "ayalon",
    "shiloah", "karnit",

    # קופות חולים ובריאות
    "clalit", "maccabi", "meuhedet", "leumit",

    # דואר ומשלוחים
    "israelpost", "daka90", "israeldakdak",
    "ups", "fedex", "dhl",

    # ממשלה ומוסדות ציבוריים
    "gov", "mof", "misim", "mas-hachnasa",
    "btl", "bituahleumi", "bitouahleumi",
    "nii",
    "moked106",
    "arnona",
    "iriya", "municipality",
    "kvish6", "iroads", "netivei-israel",
    "pazi", "sonol", "delek", "paz",
    "misrad-habriyut", "misradhabriyut",
    "misrad-hachinuch", "rama",

    # חברות תשתית ותקשורת
    "bezek", "bezeq", "partner", "cellcom", "hot", "yes",
    "012", "013", "019", "ravtech",
    "iec", "hagihon", "mekorot",

    # קמעונאות
    "shufersal", "ramilevi", "ramilevy", "victory",
    "superpharm", "super-pharm", "ksp", "ivory",

    # שירותים ממשלתיים דיגיטליים
    "gov-il", "mydigital", "digitalil",
    "tzahal", "idf",
    "misrad", "rashut",

    # גלובליים נפוצים
    "apple", "google", "microsoft", "amazon",
    "facebook", "instagram", "netflix", "whatsapp",
    "tiktok", "spotify", "telegram",
]

LOOKALIKE_MAP = {
    "0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "6": "b", "8": "b",
    "@": "a", "vv": "w",
}

SUSPICIOUS_KEYWORDS = [
    # אנגלית
    "login", "signin", "verify", "verification", "secure", "security",
    "account", "update", "confirm", "banking", "wallet", "password",
    "credential", "suspend", "urgent", "alert", "validate", "authenticate",
    "payment", "invoice", "debt", "fine", "penalty", "overdue",
    "tracking", "delivery", "parcel", "package", "shipment",
    # עברית (URL-encoded ו-plain)
    "כניסה", "אימות", "חשבון", "בנק", "עדכון",
    "תשלום", "חוב", "קנס", "דוח", "הוראת-קבע", "הוראת קבע",
    "ביטוח-לאומי", "מס-הכנסה", "ארנונה", "כביש6", "כביש-6",
    "עיריית", "רשות", "משרד", "ממשלה",
    "חבילה", "משלוח", "מכס", "דואר", "איסוף",
    "החזר", "זיכוי", "פיצוי", "מענק",
]

SUSPICIOUS_TLDS = {
    ".tk", ".ml", ".ga", ".cf", ".gq", ".top", ".xyz", ".click",
    ".download", ".loan", ".win", ".racing", ".date", ".faith",
    ".stream", ".gdn", ".men", ".work",
}

# Israeli second-level domains that form 3-part TLDs: <brand>.<sld>.il
_IL_SLD = {"co", "org", "net", "gov", "ac", "muni"}

# Exact registered roots that contain short brand tokens but are legitimate
_BRAND_DOMAIN_WHITELIST = {
    "bit.co.il",
    "max.co.il",
    "hot.co.il",
    "partner.co.il",
}

# Weighted signal strengths — higher = more confident phishing indicator
_HEURISTIC_WEIGHTS = {
    "ip":        5,  # IP address as domain (near-zero legitimate consumer use)
    "subdomain": 4,  # brand name in subdomain but not root
    "coil":      4,  # .co.il- SMS phishing pattern
    "tld":       3,  # suspicious free TLD
    "hyphens":   2,  # excessive hyphens (>=3)
    "subs":      2,  # excessive subdomains (>=4 dots)
    "longname":  1,  # very long domain root
    "keyword":   1,  # per suspicious keyword (capped at 3)
}


def _registered_domain(domain: str) -> tuple[str, str]:
    """Return (subdomain_prefix, registered_root) with correct .co.il handling.

    Examples:
        "www.bankhapoalim.co.il" → ("www", "bankhapoalim.co.il")
        "paypal.evil.co.il"      → ("paypal", "evil.co.il")
        "www.google.com"         → ("www", "google.com")
        "misim.gov.il"           → ("", "misim.gov.il")
    """
    parts = domain.lower().split(".")
    if len(parts) >= 3 and parts[-2] in _IL_SLD and parts[-1] == "il":
        root      = ".".join(parts[-3:])       # brand.co.il
        subdomain = ".".join(parts[:-3])        # everything left of brand
    elif len(parts) >= 2:
        root      = ".".join(parts[-2:])        # brand.com
        subdomain = ".".join(parts[:-2])
    else:
        root, subdomain = domain, ""
    return subdomain, root


def _normalize(s: str) -> str:
    s = s.lower()
    for k, v in LOOKALIKE_MAP.items():
        s = s.replace(k, v)
    return s


def extract_domain(url: str) -> str:
    m = re.search(r"(?:https?://)?([^/?\s]+)", url)
    return m.group(1).lower() if m else url.lower()


def check_lookalike(url: str) -> dict:
    domain = extract_domain(url)

    # Fast-pass: known-legitimate .gov.il subdomains and exact whitelist entries
    _, root = _registered_domain(domain)
    if root in _BRAND_DOMAIN_WHITELIST or root.endswith(".gov.il"):
        return {"lookalike": False, "brands": []}

    # Decode Punycode/IDN so homoglyph xn-- domains are normalized before matching
    try:
        domain_decoded = domain.encode("ascii").decode("idna")
    except (UnicodeError, UnicodeDecodeError):
        domain_decoded = domain

    norm = _normalize(domain_decoded)
    # Require token length >= 4 to avoid noise from "bit", "max", "hot", "gov"
    hits = [b for b in BRANDS if len(b) >= 4 and b in norm and b not in domain_decoded]
    return {"lookalike": bool(hits), "brands": hits}


async def check_domain_age(url: str) -> dict:
    domain = extract_domain(url)
    _, root = _registered_domain(domain)
    try:
        w = await asyncio.wait_for(
            asyncio.to_thread(whois.whois, root),
            timeout=8.0,
        )
        created = w.creation_date
        if isinstance(created, list):
            created = created[0]
        if created:
            if created.tzinfo is None:
                created = created.replace(tzinfo=timezone.utc)
            age_days = (datetime.now(timezone.utc) - created).days
            return {"age_days": age_days, "new_domain": age_days < 30}
    except asyncio.TimeoutError:
        pass
    except Exception:
        pass
    return {"age_days": None, "new_domain": None}


def check_heuristics(url: str) -> dict:
    domain = extract_domain(url)
    flags  = []
    score  = 0

    def _add(label: str, weight_key: str) -> None:
        nonlocal score
        flags.append(label)
        score += _HEURISTIC_WEIGHTS[weight_key]

    # IP address as domain
    if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", domain):
        _add("כתובת IP במקום דומיין", "ip")

    # Excessive subdomains — threshold 4 to avoid flagging www.brand.co.il (3 dots)
    if domain.count(".") >= 4:
        _add("יותר מדי תתי-דומיינים", "subs")

    # Suspicious TLD
    for tld in SUSPICIOUS_TLDS:
        if domain.endswith(tld):
            _add(f"סיומת דומיין חשודה ({tld})", "tld")
            break

    # Long domain name (first label only)
    first_label = domain.split(".")[0]
    if len(first_label) > 30:
        _add("שם דומיין ארוך מאוד", "longname")

    # Multiple hyphens
    if domain.count("-") >= 3:
        _add("יותר מדי מקפים בדומיין", "hyphens")

    # Suspicious keywords — unquote so Hebrew %D7%... paths match
    url_decoded   = unquote(url).lower()
    keyword_hits  = [k for k in SUSPICIOUS_KEYWORDS if k in url_decoded]
    for kw in keyword_hits[:3]:
        _add(f"מילת מפתח חשודה: {kw}", "keyword")

    # Brand name in subdomain but not in registered root (classic phishing)
    subdomain_part, root_part = _registered_domain(domain)
    if subdomain_part:
        for brand in BRANDS:
            if len(brand) >= 4 and brand in subdomain_part and brand not in root_part:
                _add(f"מותג '{brand}' מופיע בתת-דומיין בלבד — חשוד מאוד", "subdomain")
                break

    # Israeli SMS phishing pattern: brand.co.il-randomdomain.xyz
    if re.search(r"\.co\.il[-.]", domain):
        _add("דומיין מחקה כתובת ישראלית (.co.il) — תבנית פישינג נפוצה ב-SMS", "coil")

    return {"heuristic_flags": flags, "heuristic_score": score}
