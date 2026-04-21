import re
import whois
from datetime import datetime, timezone

BRANDS = [
    # בנקים וכרטיסי אשראי
    "paypal", "visa", "mastercard",
    "bankhapoalim", "bankleumi", "hapoalim", "leumi", "poalim",
    "mizrahi", "discount", "fibi", "otzar", "benleumi",
    "isracard", "max", "cal", "bit", "pepper",

    # ממשלה ומוסדות ציבוריים
    "gov", "mof", "misim", "mas-hachnasa",         # משרד האוצר / מס הכנסה
    "btl", "bituahleumi", "bitouahleumi",           # ביטוח לאומי
    "nii",                                          # National Insurance Institute
    "moked106",                                     # עיריות / מוקד 106
    "arnona",                                       # ארנונה
    "iriya", "municipality",                        # עיריות
    "kvish6", "iroads", "netivei-israel",           # כביש 6 / נתיבי ישראל
    "pazi", "sonol", "delek", "paz",                # דלק / תחנות דלק

    # חברות תשתית ותקשורת
    "bezek", "bezeq", "partner", "cellcom", "hot",
    "012", "013", "019", "ravtech",
    "iec", "hagihon", "mekorot",                    # חשמל / מים

    # שירותים ממשלתיים דיגיטליים
    "gov-il", "mydigital", "digitalil",
    "tzahal", "idf",
    "misrad", "rashut",

    # גלובליים נפוצים
    "apple", "google", "microsoft", "amazon",
    "facebook", "instagram", "netflix", "whatsapp",
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
    # עברית
    "כניסה", "אימות", "חשבון", "בנק", "עדכון",
    "תשלום", "חוב", "קנס", "דוח", "הוראת-קבע", "הוראת קבע",
    "ביטוח-לאומי", "מס-הכנסה", "ארנונה", "כביש6", "כביש-6",
    "עיריית", "רשות", "משרד", "ממשלה",
]

SUSPICIOUS_TLDS = {
    ".tk", ".ml", ".ga", ".cf", ".gq", ".top", ".xyz", ".click",
    ".download", ".loan", ".win", ".racing", ".date", ".faith",
    ".stream", ".gdn", ".men", ".work",
}


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
    norm = _normalize(domain)
    hits = [b for b in BRANDS if b in norm and b not in domain]
    return {"lookalike": bool(hits), "brands": hits}


def check_domain_age(url: str) -> dict:
    domain = extract_domain(url)
    parts = domain.split(".")
    root = ".".join(parts[-2:]) if len(parts) >= 2 else domain
    try:
        w = whois.whois(root)
        created = w.creation_date
        if isinstance(created, list):
            created = created[0]
        if created:
            if created.tzinfo is None:
                created = created.replace(tzinfo=timezone.utc)
            age_days = (datetime.now(timezone.utc) - created).days
            return {"age_days": age_days, "new_domain": age_days < 30}
    except Exception:
        pass
    return {"age_days": None, "new_domain": None}


def check_heuristics(url: str) -> dict:
    domain = extract_domain(url)
    flags = []

    # IP address as domain
    if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", domain):
        flags.append("כתובת IP במקום דומיין")

    # excessive subdomains (3+)
    if domain.count(".") >= 3:
        flags.append("יותר מדי תתי-דומיינים")

    # suspicious TLD
    for tld in SUSPICIOUS_TLDS:
        if domain.endswith(tld):
            flags.append(f"סיומת דומיין חשודה ({tld})")
            break

    # long domain name
    root = domain.split(".")[0]
    if len(root) > 30:
        flags.append("שם דומיין ארוך מאוד")

    # multiple hyphens
    if domain.count("-") >= 3:
        flags.append("יותר מדי מקפים בדומיין")

    # suspicious keywords in URL
    url_lower = url.lower()
    keyword_hits = [k for k in SUSPICIOUS_KEYWORDS if k in url_lower]
    if keyword_hits:
        flags.append(f"מילות מפתח חשודות: {', '.join(keyword_hits[:3])}")

    # brand name in subdomain but not root (classic phishing pattern)
    parts = domain.split(".")
    if len(parts) >= 3:
        subdomain = ".".join(parts[:-2])
        root_domain = parts[-2]
        for brand in BRANDS:
            if brand in subdomain and brand not in root_domain:
                flags.append(f"מותג '{brand}' מופיע בתת-דומיין בלבד — חשוד מאוד")
                break

    return {"heuristic_flags": flags, "heuristic_score": len(flags)}
