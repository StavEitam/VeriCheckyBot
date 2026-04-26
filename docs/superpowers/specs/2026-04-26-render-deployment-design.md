# VeriBot — Render Cloud Deployment Design
**Date:** 2026-04-26
**Scope:** Task 1 — Deploy VeriBot to Render free tier for 24/7 operation

---

## Constraints

- **Platform:** Render free tier (0 USD/month)
- **No persistent disk** — Render persistent disk is a paid feature; SQLite lives in ephemeral container filesystem and resets on restart/redeploy. This is acceptable: SQLite is a pure TTL cache, not user data.
- **Polling mode** — `bot.run_polling()` stays. Webhooks would require a public HTTPS endpoint + Render web service; polling works on a Render background worker at no added cost.
- **System dependency** — `pytesseract` requires `tesseract-ocr` binary (apt). Cannot be pip-installed. Dockerfile is mandatory.
- **Secrets** — All 7 API keys remain env vars set in Render dashboard. `.env` file is local-only, `.dockerignore`d and gitignored.

---

## Files to Create / Modify

### Create: `Dockerfile`

```
FROM python:3.12-slim

RUN apt-get update && apt-get install -y \
    tesseract-ocr \
    tesseract-ocr-eng \
    tesseract-ocr-heb \
    --no-install-recommends && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

CMD ["python", "bot.py"]
```

### Create: `render.yaml`

```yaml
services:
  - type: worker
    name: veribot
    runtime: docker
    plan: free
    envVars:
      - key: TELEGRAM_TOKEN
        sync: false
      - key: VIRUSTOTAL_KEY
        sync: false
      - key: ANTHROPIC_KEY
        sync: false
      - key: URLSCAN_KEY
        sync: false
      - key: GOOGLE_SAFE_BROWSING_KEY
        sync: false
      - key: PHISHTANK_KEY
        sync: false
      - key: ABUSEIPDB_KEY
        sync: false
```

Note: `runtime: docker` tells Render to use the `Dockerfile` in the repo root. `type: worker` is correct for a long-running polling bot — it does not expect HTTP traffic and has no port binding. Do NOT use `type: web` (requires a port listener). No `startCommand` needed — the `CMD` in Dockerfile takes precedence.

### Create: `.dockerignore`

```
venv/
.env
__pycache__/
*.pyc
*.db
.claude/
docs/
tests/
*.md
.pytest_cache/
```

### Modify: `requirements.txt`

Pin all versions. Current file is unpinned — unpinned deps cause non-reproducible builds.

```
python-telegram-bot==22.7
anthropic==0.40.0
httpx==0.28.1
python-dotenv==1.0.1
python-whois==0.9.6
pytesseract==0.3.13
Pillow==11.2.1
```

(Versions match what is currently installed in local venv.)

### Modify: `translator.py`

Switch from `anthropic.Anthropic` (sync, blocking) to `anthropic.AsyncAnthropic` (async, non-blocking).

**Root cause of current problem:** `client.messages.create(...)` is a synchronous HTTP call. Called from inside `analyze_url()` which runs in asyncio event loop. The sync call blocks the entire event loop for the duration of the Anthropic API call (~500ms–2s), preventing concurrent Telegram updates from being processed.

**Fix:** `AsyncAnthropic` client + `async def get_verdict` + `await client.messages.create`.

No logic changes — only `def` → `async def`, `client.messages.create` → `await client.messages.create`, `Anthropic` → `AsyncAnthropic`.

### Modify: `bot.py`

`get_verdict` becomes async, so all call sites need `await`:
- `analyze_url()` already async — just add `await` before `get_verdict(...)`

### Modify: `cache.py`

`DB_PATH` reads from env var for flexibility:
```python
DB_PATH = os.getenv("DB_PATH", "veri_cache.db")
```

On Render (no disk): default `veri_cache.db` in working dir — ephemeral but functional.
Future: if paid disk added, set `DB_PATH=/data/veri_cache.db` in Render dashboard, zero code change needed.

---

## Deployment Steps (Manual, one-time)

1. Push repo to GitHub (ensure `.env` is in `.gitignore`)
2. Rotate all API keys (old keys are in committed `.env`)
3. Create Render account → New → Background Worker → connect GitHub repo
4. Set all 7 env vars in Render dashboard
5. Deploy — Render detects Dockerfile, builds, starts polling

---

## What Resets on Restart

- `veri_cache.db` — all cached scan results. Effect: cold cache, next scan pays full API latency. No user data lost.

## What Persists Across Restarts

- Nothing stateful. Bot is stateless per message. Correct.

---

## Out of Scope

- Task 2: Architecture review
- Task 3: Hebrew HTML presentation
- Webhook migration
- PostgreSQL migration
- Rate limiting / group chat support
