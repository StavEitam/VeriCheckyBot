# Veri — Telegram Phishing Detection Bot

## What This Is

Veri is a Telegram bot that detects phishing and scam links in real time. Users send a URL or a screenshot, and the bot responds in **Hebrew** with a clear verdict: safe, suspicious, or dangerous — and what to do about it.

Target audience: Israeli users who receive suspicious links via WhatsApp, SMS, email, or Telegram and want a quick, trustworthy second opinion.

---

## Goals

- Detect phishing/scam URLs with high accuracy using multiple data sources
- Respond entirely in Hebrew, in plain language non-technical users understand
- Work inside Telegram (no app install, no account, zero friction)
- Stay free to run (all APIs have free tiers sufficient for personal/small group use)
- Be deployable by a solo developer with no DevOps background

---

## How It Works — Flow

```
User sends message/photo
        ↓
bot.py — Telegram handler
        ↓
Extract URLs (regex or OCR from screenshot)
        ↓
For each URL:
  ├── analyzer/url_checker.py
  │     ├── VirusTotal API — threat score (malicious/suspicious/harmless counts)
  │     └── URLScan.io API — redirect chain, final URL, malicious verdict + tags
  ├── analyzer/domain_intel.py
  │     ├── Whois — domain creation date → flag if < 30 days old
  │     └── Lookalike detection — catches brand impersonation (paypal→paypa1, etc.)
  └── cache.py — SQLite cache (1hr TTL) to avoid burning API quotas
        ↓
translator.py — sends all signals to Claude API
        ↓
Claude responds in Hebrew: summary line + risk level + action recommendation
        ↓
Bot replies to user in Hebrew
```

---

## Tech Stack

| Component | Technology |
|-----------|------------|
| Bot framework | python-telegram-bot 22.7 |
| URL threat scanning | VirusTotal API (v3) |
| Redirect/domain analysis | URLScan.io API |
| Domain age & lookalike | python-whois + custom logic |
| OCR (screenshot → URL) | pytesseract + Pillow |
| Hebrew verdict generation | Anthropic Claude API (claude-haiku-4-5) |
| Caching | SQLite (via cache.py) |
| Secrets management | python-dotenv (.env file) |
| Runtime | Python 3.11+, venv |

---

## File Structure

```
Veri/
├── .env                     ← API keys (gitignored)
├── .gitignore
├── PROJECT.md               ← this file
├── requirements.txt
├── bot.py                   ← Telegram handlers, main entry point
├── config.py                ← loads .env into named constants
├── cache.py                 ← SQLite cache with TTL
├── translator.py            ← Claude API call → Hebrew verdict string
└── analyzer/
    ├── __init__.py
    ├── url_checker.py       ← VirusTotal + URLScan.io integration
    ├── domain_intel.py      ← Whois age check + lookalike brand detection
    └── ocr.py               ← extract URLs from screenshot images
```

---

## API Keys (stored in .env)

```
TELEGRAM_TOKEN      — Telegram BotFather token
VIRUSTOTAL_KEY      — VirusTotal v3 API key (500 req/day free)
ANTHROPIC_KEY       — Anthropic API key (pay-per-use, no subscription needed)
URLSCAN_KEY         — URLScan.io API key (free tier)
```

The `.env` file is gitignored. Never commit it.

---

## Running the Bot

```bash
cd "path/to/Veri"
venv/Scripts/activate        # Windows
python bot.py
```

Bot polls Telegram. Send it any message with a URL or a screenshot containing a URL.

---

## Bot Behavior

| Input | Bot does |
|-------|----------|
| Text with URL(s) | Scans up to 3 URLs, replies with Hebrew verdict per URL |
| Photo/screenshot | OCR extracts URLs, then same scan flow |
| Text without URL | Replies asking for a link or screenshot |
| `/start` | Greeting + instructions in Hebrew |

---

## Hebrew Verdict Format (Claude output)

Claude is prompted as a cybersecurity expert and returns:
1. **Summary line** — what this URL is / looks like
2. **Risk level** — גבוהה / בינונית / נמוכה (High / Medium / Low)
3. **Recommended action** — e.g., "אל תלחץ על הקישור", "נראה בטוח אך היה זהיר"

Model used: `claude-haiku-4-5-20251001` (fast + cheap, ideal for this use case)

---

## Brand Lookalike Detection

`domain_intel.py` normalizes common character substitutions:
- `0→o`, `1→l`, `3→e`, `4→a`, `5→s`, `vv→w`, etc.

Brands monitored: PayPal, Apple, Google, Microsoft, Amazon, Facebook, Instagram, Netflix, Bank Hapoalim, Bank Leumi, Isracard, Max, Bit, Pepper, Poalim.

---

## Caching Strategy

SQLite DB (`veri_cache.db`, auto-created on first run).
- Cache key: `vt:<url>` or `us:<url>`
- TTL: 1 hour
- Purpose: avoid re-scanning the same URL repeatedly, stay within free API quotas

---

## OCR Note

Requires **Tesseract** installed on the system:
- Windows: https://github.com/UB-Mannheim/tesseract/wiki
- Language packs needed: `eng` + `heb`

---

## Current Status

- [x] Step 1 — API keys collected, .env created, venv set up, all dependencies installed
- [x] Step 2 — All core code files written:
  - `config.py`, `cache.py`, `translator.py`, `bot.py`
  - `analyzer/url_checker.py`, `analyzer/domain_intel.py`, `analyzer/ocr.py`
- [ ] Step 3 — Testing: run locally, test with real URLs, verify Hebrew output
- [ ] Step 4 — Deploy to Render (free tier, always-on)
- [ ] Step 5 — (Optional) Add group chat support, rate limiting, /report command

---

## Known Constraints

- VirusTotal free tier: 500 req/day — cache mitigates this
- URLScan scan takes ~10–30 seconds (async wait built in)
- OCR accuracy depends on screenshot quality
- Bot currently handles up to 3 URLs per message (capped to protect quotas)
- No persistent user state — stateless per message

---

## Next Steps (when continuing development)

1. **Test locally** — run `python bot.py`, send real suspicious URLs
2. **Tune Hebrew prompt** — adjust Claude system prompt if verdicts feel off
3. **Deploy to Render** — free web service, add `render.yaml` or just set start command to `python bot.py`
4. **Add error resilience** — retry logic for URLScan timeouts
5. **Group chat support** — respond only when bot is @mentioned
