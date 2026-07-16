# Veri — Telegram Phishing Detection Bot 🛡️

A Telegram bot that detects phishing and scam links in real time, responding in **Hebrew** with a clear verdict: safe, suspicious, or dangerous — and what to do about it.

Built for Israeli users who receive suspicious links via WhatsApp, SMS, email, or Telegram and want a fast, trustworthy second opinion — no app install, no account required.

---

## Features

- **Multi-source threat intelligence** — cross-references VirusTotal, URLScan.io, Google Safe Browsing, PhishTank, OpenPhish, and AbuseIPDB
- **URL shortener resolution** — automatically expands bit.ly, t.co, did.li and other shorteners before scanning
- **Brand lookalike detection** — catches impersonation of PayPal, Bank Hapoalim, Apple, Amazon, and 15+ other brands
- **Screenshot OCR** — extracts URLs from images using Tesseract
- **Hebrew AI verdict** — Claude generates a human-readable security verdict in plain Hebrew
- **Smart caching** — SQLite cache avoids re-scanning known URLs, preserving free-tier API quotas
- **Fast-path short-circuit** — skips slow APIs when a confirmed threat is already detected

---

## How It Works

```
User sends message / photo
         ↓
bot.py — Telegram handler
         ↓
Extract URLs (regex or OCR from screenshot)
         ↓
For each URL:
  ├── Unshorten (if bit.ly / t.co / etc.)
  │
  ├── Wave 1 — fast checks (~1-2s each)
  │     ├── Google Safe Browsing
  │     ├── PhishTank
  │     ├── OpenPhish
  │     ├── AbuseIPDB
  │     ├── Brand lookalike detection
  │     └── Heuristic flags
  │
  └── Wave 2 — deep checks (15-70s) — skipped if Wave 1 confirms threat
        ├── VirusTotal API (malicious / suspicious / harmless engine counts)
        ├── URLScan.io (redirect chain, final URL, risk score, tags)
        └── WHOIS domain age check
         ↓
translator.py — sends all signals to Claude API
         ↓
Claude responds in Hebrew: target domain + risk level + findings + recommendation
         ↓
Bot replies to user
```

---

## Tech Stack

| Component | Technology |
|-----------|------------|
| Bot framework | python-telegram-bot 22.7 |
| URL threat scanning | VirusTotal API v3 |
| Redirect / sandbox analysis | URLScan.io API |
| Known phishing database | PhishTank API |
| Real-time phishing feed | OpenPhish (public feed) |
| Safe browsing lookup | Google Safe Browsing API v4 |
| IP reputation | AbuseIPDB API |
| Domain age & lookalike | python-whois + custom heuristics |
| OCR (screenshot → URL) | pytesseract + Pillow |
| Hebrew verdict generation | Anthropic Claude API (`claude-haiku-4-5`) |
| Caching | SQLite via `cache.py` (1-hour TTL) |
| HTTP client | httpx (async) |
| Secrets management | python-dotenv |
| Runtime | Python 3.11+ |

---

## Project Structure

```
Veri/
├── .env                     ← API keys (gitignored — never commit)
├── .env.example             ← template for required keys
├── .gitignore
├── requirements.txt
├── bot.py                   ← Telegram handlers, main entry point
├── config.py                ← loads .env into named constants
├── cache.py                 ← SQLite cache with TTL
├── translator.py            ← builds prompt + calls Claude API → Hebrew verdict
├── test_sources.py          ← manual integration test harness
├── tests/                   ← automated test suite
└── analyzer/
    ├── url_checker.py       ← VirusTotal, URLScan, GSB, PhishTank, OpenPhish, AbuseIPDB
    ├── domain_intel.py      ← WHOIS age check + brand lookalike detection + heuristics
    └── ocr.py               ← extract URLs from screenshot images
```

---

## Setup

### Prerequisites

- Python 3.11+
- [Tesseract OCR](https://github.com/UB-Mannheim/tesseract/wiki) installed on the system
  - Required language packs: `eng` + `heb`

### 1. Clone and create a virtual environment

```bash
git clone <repo-url>
cd Veri
python -m venv venv
venv\Scripts\activate        # Windows
# source venv/bin/activate   # macOS / Linux
```

### 2. Install dependencies

```bash
pip install -r requirements.txt
```

### 3. Configure API keys

Copy `.env.example` to `.env` and fill in your keys:

```env
TELEGRAM_TOKEN=your_telegram_token_here
VIRUSTOTAL_KEY=your_virustotal_key_here
ANTHROPIC_KEY=your_anthropic_key_here
URLSCAN_KEY=your_urlscan_key_here
GOOGLE_SAFE_BROWSING_KEY=your_google_safe_browsing_key_here
```

> **Never commit `.env` — it is gitignored.**

#### Obtaining API keys

| Key | Source | Free tier |
|-----|--------|-----------|
| `TELEGRAM_TOKEN` | [@BotFather](https://t.me/BotFather) on Telegram | Free |
| `VIRUSTOTAL_KEY` | [virustotal.com](https://www.virustotal.com) → API | 500 req/day |
| `ANTHROPIC_KEY` | [console.anthropic.com](https://console.anthropic.com) | Pay-per-use |
| `URLSCAN_KEY` | [urlscan.io](https://urlscan.io) → Account | Free tier |
| `GOOGLE_SAFE_BROWSING_KEY` | Google Cloud Console → Safe Browsing API | Free tier |

PhishTank and AbuseIPDB keys are optional — the bot degrades gracefully if they are absent.

### 4. Run the bot

```bash
python bot.py
```

The bot starts polling Telegram. Send it any message containing a URL or a screenshot.

---

## Bot Behavior

| Input | Response |
|-------|----------|
| Text with URL(s) | Scans up to 3 URLs, replies with Hebrew verdict per URL |
| Photo / screenshot | OCR extracts URLs, then scans as above |
| Text without URL | Asks the user to paste the message or send a screenshot |
| `/start` | Greeting and usage instructions in Hebrew |

---

## Hebrew Verdict Format

Claude is prompted as an Israeli cybersecurity expert and returns:

```
🔗 יעד הקישור: [final domain or "unknown"]
⚠️ רמת סיכון: גבוהה / בינונית / לא ניתן לאמת
📋 ממצאים: [2–3 lines summarising what was found]
🛑 המלצה: [specific action — e.g., "אל תלחץ על הקישור"]
```

Key rules baked into the Claude prompt:
- Never says "the link is safe" — only "no known threats found"
- Shortened links are always flagged as unverifiable
- When in doubt, warns rather than reassures

---

## Brand Lookalike Detection

`analyzer/domain_intel.py` normalises common character substitutions before comparing against a brand list:

| Substitution | Example |
|---|---|
| `0 → o` | `paypa0.com` |
| `1 → l` | `app1e.com` |
| `3 → e` | `n3tflix.com` |
| `vv → w` | `vvhatsapp.com` |

**Monitored brands:** PayPal, Apple, Google, Microsoft, Amazon, Facebook, Instagram, Netflix, Bank Hapoalim, Bank Leumi, Isracard, Max, Bit, Pepper, Poalim.

---

## Caching

- **Store:** SQLite (`veri_cache.db`, auto-created on first run)
- **TTL:** 1 hour
- **Keys:** `vt:<url>`, `us:<url>`, `gsb:<url>`, `pt:<url>`, `abuse:<domain>`, `openphish:feed`
- **Purpose:** avoid re-scanning the same URL within the same hour, protecting free API quotas

---

## Known Constraints

- VirusTotal free tier: 500 requests/day
- URLScan deep-scan takes 10–70 seconds (async polling built in)
- OCR accuracy depends on screenshot quality
- Bot caps at 3 URLs per message to protect API quotas
- Stateless per message — no persistent user history

---

## Deployment (Google Cloud — Always Free)

Hosted on a **Google Cloud e2-micro VM** (us-central1) — permanently free tier.

```bash
# On the VM:
git clone https://github.com/StavEitam/VeriCheckyBot.git && cd VeriCheckyBot
python3 -m venv venv && source venv/bin/activate && pip install -r requirements.txt
# Create .env with API keys, then:
python3 bot.py
```

To keep the bot running after logout, use systemd or `nohup python3 bot.py &`.

---

## Roadmap

- [x] Deploy to Google Cloud e2-micro (free tier, always-on)
- [ ] Retry logic for URLScan timeouts
- [ ] Group chat support (respond only when @mentioned)
- [ ] Per-user rate limiting
- [ ] `/report` command to flag false negatives
