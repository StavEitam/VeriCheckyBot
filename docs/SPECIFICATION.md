# Veri — System Specification

Telegram-based phishing & scam detection bot for Israeli users. Analyzes URLs via multi-source threat intelligence and returns Hebrew security verdicts using Claude AI.

---

## Architecture Flow Diagram

```mermaid
flowchart TD
    USER([👤 Telegram User])

    subgraph INPUT["Input Layer"]
        TXT["Text Message\nwith URL"]
        IMG["Photo / Screenshot"]
        CMD["/start Command"]
    end

    subgraph BOT["bot.py — Orchestration"]
        EXT[extract_urls]
        OCR[ocr.extract_urls_from_image]
        ANA[analyze_url\nPipeline Controller]
        CAP[Cap at 3 URLs]
    end

    subgraph PHASE0["Phase 0 — Local Analysis  0ms"]
        HEU[check_heuristics\nWeighted Score 0–15]
        LOO[check_lookalike\nBrand Impersonation]
        SHORT["is_shortener?\nunshorten_url"]
    end

    subgraph PHASE1["Phase 1 — Fast APIs  ~1–2s"]
        GSB[Google Safe Browsing]
        PT[PhishTank]
        OP[OpenPhish Feed\nPre-cached 1h]
        ABUSE[AbuseIPDB\nIP Reputation]
        CERTIL[CERT-IL\nStub]
    end

    EARLY{Threat\nConfirmed?}

    subgraph PHASE2["Phase 2 — Deep APIs  ~15–45s"]
        VT[VirusTotal\n70+ AV engines]
        US[URLScan.io\nSandbox]
        WHOIS[Domain Age\nWHOIS lookup]
    end

    subgraph AI["Phase 3 — Verdict  Claude Haiku"]
        PROMPT[Build Hebrew Prompt\nThreat findings only]
        CLAUDE[claude-haiku-4-5\nAnthropic API]
        VERDICT["Hebrew Verdict\n🔗 יעד / ⚠️ סיכון / 📋 ממצאים / 🛑 המלצה"]
    end

    CACHE[(SQLite Cache\nveri_cache.db)]

    USER --> TXT & IMG & CMD
    TXT --> EXT --> CAP
    IMG --> OCR --> EXT
    CMD --> BOT
    CAP --> ANA

    ANA --> PHASE0
    SHORT --> ANA
    HEU & LOO --> EARLY

    ANA --> PHASE1
    GSB & PT & OP & ABUSE & CERTIL --> EARLY

    EARLY -->|YES skip Phase 2| AI
    EARLY -->|NO| PHASE2
    VT & US & WHOIS --> AI

    PROMPT --> CLAUDE --> VERDICT --> USER

    PHASE1 <-->|TTL cache| CACHE
    PHASE2 <-->|TTL cache| CACHE
```

---

## Sequence Diagram

```mermaid
sequenceDiagram
    actor User as 👤 User (Telegram)
    participant Bot as bot.py
    participant Cache as SQLite Cache
    participant Intel as url_checker.py
    participant Domain as domain_intel.py
    participant VT as VirusTotal API
    participant URLScan as URLScan.io
    participant GSB as Google Safe Browsing
    participant PT as PhishTank
    participant OP as OpenPhish
    participant AbuseIPDB as AbuseIPDB
    participant AI as Claude Haiku

    User->>Bot: Send message / photo with URL
    activate Bot

    alt Photo message
        Bot->>Bot: ocr.extract_urls_from_image()
    else Text message
        Bot->>Bot: extract_urls() via regex
    end

    Note over Bot: Cap at 3 URLs. For each URL:

    Bot->>Bot: is_shortener(url)?
    alt Shortened URL
        Bot->>Intel: unshorten_url(url) → follow redirects
        Intel-->>Bot: final_url
    end

    Bot->>User: ⏳ בודק קישור...

    par Phase 0 — Local (0ms)
        Bot->>Domain: check_lookalike(url)
        Domain-->>Bot: {lookalike, brands}
        Bot->>Domain: check_heuristics(url)
        Domain-->>Bot: {flags, score}
    end

    alt heuristic_score ≥ 7
        Note over Bot: Early skip — high confidence threat
    else Normal path
        par Phase 1 — Fast APIs (~1–2s)
            Bot->>Cache: get("gsb:<url>")
            alt Cache miss
                Bot->>GSB: threatMatches:find
                GSB-->>Bot: threat_found?
                Bot->>Cache: set("gsb:<url>", result, ttl)
            end

            Bot->>Cache: get("pt:<url>")
            alt Cache miss
                Bot->>PT: checkurl POST
                PT-->>Bot: in_database, verified
                Bot->>Cache: set("pt:<url>", result, 3600)
            end

            Bot->>Cache: get("openphish:feed")
            alt Cache miss
                Bot->>OP: GET feed.txt
                OP-->>Bot: URL list
                Bot->>Cache: set("openphish:feed", list, 3600)
            end

            Bot->>AbuseIPDB: check IP reputation
            AbuseIPDB-->>Bot: abuse_score, reports
        end

        alt Confirmed threat (GSB / PhishTank / OpenPhish)
            Note over Bot: Early exit — skip Phase 2
        else No confirmed threat
            par Phase 2 — Deep APIs (~15–45s)
                Bot->>Cache: get("vt:<url>")
                alt Cache miss
                    Bot->>VT: POST + adaptive poll
                    VT-->>Bot: malicious, suspicious counts
                    Bot->>Cache: set("vt:<url>", result, 3600)
                end

                Bot->>Cache: get("us:<url>")
                alt Cache miss
                    Bot->>URLScan: submit + poll
                    URLScan-->>Bot: final_url, score, tags
                    Bot->>Cache: set("us:<url>", result, 3600)
                end

                Bot->>Domain: check_domain_age(url)
                Domain-->>Bot: age_days, new_domain
            end
        end
    end

    Bot->>AI: get_verdict(url, all_results)
    Note over AI: Build Hebrew prompt\nOnly threat-positive sources included
    AI-->>Bot: Hebrew verdict string

    Bot->>User: 🔗 יעד הקישור / ⚠️ רמת סיכון / 📋 ממצאים / 🛑 המלצה
    deactivate Bot
```

---

## UML Class Diagram

```mermaid
classDiagram
    class TelegramBot {
        +Application app
        +extract_urls(text: str) List~str~
        +handle_message(update, context) None
        +handle_photo(update, context) None
        +analyze_url(url: str) str
        +_prewarm_feeds(app) None
        +main() None
    }

    class URLChecker {
        +SHORTENERS: Set~str~
        +is_shortener(url: str) bool
        +unshorten_url(url: str) str
        +vt_scan(url: str) dict
        +urlscan_scan(url: str) dict
        +google_safe_browsing(url: str) dict
        +phishtank_check(url: str) dict
        +openphish_check(url: str) dict
        +abuseipdb_check(url: str) dict
        +certil_check(url: str) dict
    }

    class DomainIntel {
        +IL_SLD: Set~str~
        +BRANDS: Dict~str, list~
        +SUSPICIOUS_KEYWORDS: List~str~
        +SUSPICIOUS_TLDS: Set~str~
        +_HEURISTIC_WEIGHTS: Dict~str, int~
        +_registered_domain(domain: str) Tuple~str,str~
        +check_lookalike(url: str) dict
        +check_domain_age(url: str) dict
        +check_heuristics(url: str) dict
    }

    class OCR {
        +extract_urls_from_image(image_bytes: bytes) List~str~
    }

    class Translator {
        +SYSTEM: str
        +get_verdict(url, vt, us, domain, gsb, pt, op, abuse, certil, final_url, was_shortened) str
    }

    class Cache {
        +DB_PATH: str
        +init_db() None
        +get(key: str) Any
        +set(key: str, value: Any, ttl: int) None
    }

    class Config {
        +TELEGRAM_TOKEN: str
        +VIRUSTOTAL_KEY: str
        +ANTHROPIC_KEY: str
        +URLSCAN_KEY: str
        +GOOGLE_SAFE_BROWSING_KEY: str
        +PHISHTANK_KEY: str
        +ABUSEIPDB_KEY: str
    }

    class SQLiteDB {
        <<database>>
        +key: TEXT PK
        +value: TEXT JSON
        +expires_at: INTEGER
    }

    TelegramBot --> URLChecker : calls
    TelegramBot --> DomainIntel : calls
    TelegramBot --> OCR : calls
    TelegramBot --> Translator : calls
    TelegramBot --> Config : reads
    URLChecker --> Cache : read/write
    Translator --> Cache : read/write
    Cache --> SQLiteDB : persists
    URLChecker --> Config : reads API keys
    Translator --> Config : reads ANTHROPIC_KEY
```

---

## Use Case Diagram

```mermaid
flowchart LR
    USER(["👤 Israeli User"])
    ADMIN(["🔧 Bot Admin"])

    subgraph VERI["🛡️ Veri — Phishing Detection Bot"]
        UC1["Check text URL"]
        UC2["Check URL in screenshot"]
        UC3["Resolve shortened URL"]
        UC4["Get Hebrew verdict"]
        UC5["Detect brand impersonation"]
        UC6["Detect SMS phishing pattern"]
        UC7["Score heuristic risk"]
        UC8["Query threat intelligence APIs"]
        UC9["Cache API results"]
        UC10["Generate AI verdict"]
        UC11["Start bot / greet user"]
        UC12["Pre-warm OpenPhish feed"]
        UC13["Run test harness"]
        UC14["Run unit tests"]
    end

    subgraph EXT["External Systems"]
        VT["VirusTotal"]
        UScan["URLScan.io"]
        GSB2["Google Safe Browsing"]
        PH["PhishTank"]
        OPH["OpenPhish"]
        ABDB["AbuseIPDB"]
        CLAUDE2["Claude Haiku\nAnthropic"]
        TG["Telegram API"]
        WHOIS2["WHOIS"]
    end

    USER -->|sends link| UC1
    USER -->|sends photo| UC2
    USER -->|/start| UC11

    UC1 --> UC3
    UC1 --> UC5
    UC1 --> UC6
    UC1 --> UC7
    UC1 --> UC8
    UC2 --> UC1

    UC3 --> UC1
    UC7 -->|score ≥ 7 skip| UC10
    UC8 --> UC9
    UC8 --> UC10
    UC5 --> UC4
    UC6 --> UC4
    UC10 --> UC4
    UC4 -->|Hebrew reply| TG
    TG --> USER

    UC8 --> VT
    UC8 --> UScan
    UC8 --> GSB2
    UC8 --> PH
    UC8 --> OPH
    UC8 --> ABDB
    UC5 --> WHOIS2
    UC10 --> CLAUDE2

    ADMIN -->|startup| UC12
    ADMIN --> UC13
    ADMIN --> UC14
```

---

## Component Summary

| Component | File | Role |
|-----------|------|------|
| Telegram Handler | `bot.py` | Entry point; URL extraction; pipeline orchestration |
| Threat Intel | `analyzer/url_checker.py` | 7 external APIs; URL unshortening; cache integration |
| Domain Analysis | `analyzer/domain_intel.py` | Heuristics; lookalike; WHOIS; Israeli TLD parsing |
| OCR | `analyzer/ocr.py` | Tesseract — extract URLs from images |
| Verdict Engine | `translator.py` | Claude Haiku prompt + Hebrew output |
| Cache | `cache.py` | SQLite TTL cache; prevents quota exhaustion |
| Config | `config.py` | `.env` loader; API key constants |

## Risk Levels

| Level | Hebrew | Trigger Condition |
|-------|--------|-------------------|
| High | גבוהה | Confirmed by VT / GSB / PhishTank / OpenPhish OR heuristic ≥ 7 |
| Medium | בינונית | Heuristic score 4–6 OR new domain + suspicious signals |
| Unverified | לא ניתן לאמת | No threats found but shortened / new domain / low confidence |

## API Cache TTLs

| Source | Clean TTL | Threat TTL |
|--------|-----------|------------|
| VirusTotal | 3600s | 3600s |
| URLScan | 3600s | 3600s |
| Google Safe Browsing | 900s | 86400s |
| PhishTank | 3600s | 3600s |
| OpenPhish feed | 3600s | 3600s |
| AbuseIPDB | 3600s | 3600s |
