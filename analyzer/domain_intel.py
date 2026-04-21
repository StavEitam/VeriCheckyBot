import asyncio
import re
import whois
from datetime import datetime, timezone

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


async def check_domain_age(url: str) -> dict:
    domain = extract_domain(url)
    parts = domain.split(".")
    root = ".".join(parts[-2:]) if len(parts) >= 2 else domain
    try:
        w = await asyncio.to_thread(whois.whois, root)
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

    # Israeli SMS phishing pattern: brand.co.il-randomdomain.com
    # e.g. israelpost.co.il-track.xyz or btl.co.il-update.net
    if re.search(r"\.co\.il[-.]", domain):
        flags.append("דומיין מחקה כתובת ישראלית (.co.il) — תבנית פישינג נפוצה ב-SMS")

    return {"heuristic_flags": flags, "heuristic_score": len(flags)}
