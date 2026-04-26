# Render Cloud Deployment Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Deploy VeriBot to Render free tier for 24/7 operation with Docker, fix the blocking Anthropic call in `translator.py`, and make SQLite path configurable.

**Architecture:** Dockerfile installs system-level Tesseract dependency + Python deps. `render.yaml` declares a free-tier background worker using `runtime: docker`. `translator.py` switches to `AsyncAnthropic` to avoid blocking the asyncio event loop during Claude API calls. SQLite path is env-var-driven so a paid disk can be added later with zero code change.

**Tech Stack:** Python 3.12-slim (Docker), Tesseract OCR (apt), python-telegram-bot 22.7, anthropic 0.96.0 (AsyncAnthropic), Render free-tier worker

---

### Task 1: Pin requirements.txt

**Files:**
- Modify: `requirements.txt`

- [ ] **Step 1: Replace unpinned requirements with pinned versions**

Replace the entire contents of `requirements.txt` with:

```
python-telegram-bot==22.7
anthropic==0.96.0
httpx==0.28.1
python-dotenv==1.2.2
python-whois==0.9.6
pytesseract==0.3.13
Pillow==12.2.0
```

- [ ] **Step 2: Verify pip can parse it**

```bash
venv/Scripts/pip install -r requirements.txt --dry-run
```

Expected: `Would install ...` lines with no errors. (All packages already installed — dry-run just validates the file.)

- [ ] **Step 3: Commit**

```bash
git add requirements.txt
git commit -m "chore: pin all dependency versions for reproducible Docker builds"
```

---

### Task 2: Create `.dockerignore`

**Files:**
- Create: `.dockerignore`

- [ ] **Step 1: Create `.dockerignore`**

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
.git/
```

This prevents the 200MB+ `venv/` directory and secret `.env` from being copied into the Docker build context, dramatically speeding up `docker build`.

- [ ] **Step 2: Commit**

```bash
git add .dockerignore
git commit -m "chore: add .dockerignore to exclude venv, secrets, and dev files from Docker build"
```

---

### Task 3: Create `Dockerfile`

**Files:**
- Create: `Dockerfile`

- [ ] **Step 1: Create `Dockerfile`**

```dockerfile
FROM python:3.12-slim

RUN apt-get update && apt-get install -y \
    tesseract-ocr \
    tesseract-ocr-eng \
    tesseract-ocr-heb \
    --no-install-recommends \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

CMD ["python", "bot.py"]
```

Key decisions:
- `python:3.12-slim` — minimal base, no dev tools (reduces image size ~80%)
- `--no-install-recommends` + `rm -rf /var/lib/apt/lists/*` — further size reduction
- `COPY requirements.txt` before `COPY . .` — Docker layer cache: dep layer only rebuilds when `requirements.txt` changes, not on every code change
- No `EXPOSE` — polling bot, no inbound port needed

- [ ] **Step 2: Verify build locally (optional but recommended)**

```bash
docker build -t veribot-test .
```

Expected: Build completes, final line is `Successfully tagged veribot-test:latest` (or equivalent). If Docker not installed locally, skip — Render will build.

- [ ] **Step 3: Commit**

```bash
git add Dockerfile
git commit -m "feat: add Dockerfile with Tesseract system dependency for Render deployment"
```

---

### Task 4: Create `render.yaml`

**Files:**
- Create: `render.yaml`

- [ ] **Step 1: Create `render.yaml`**

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

`sync: false` means Render does not try to sync the value from a secret store — the value must be set manually in the Render dashboard. This is correct for manually-managed secrets.

`type: worker` = background worker service. Does not bind a port. Does not get an HTTP URL. Correct for a Telegram polling bot.

`runtime: docker` = Render uses the `Dockerfile` in the repo root. No `buildCommand` needed.

- [ ] **Step 2: Commit**

```bash
git add render.yaml
git commit -m "feat: add render.yaml for free-tier Docker worker deployment"
```

---

### Task 5: Make SQLite path configurable in `cache.py`

**Files:**
- Modify: `cache.py`

- [ ] **Step 1: Add `os` import and env-var-driven DB_PATH**

Current `cache.py` line 5:
```python
DB_PATH = "veri_cache.db"
```

Replace the top of `cache.py` (lines 1–6) with:

```python
import sqlite3
import json
import time
import os

DB_PATH = os.getenv("DB_PATH", "veri_cache.db")
TTL = 3600  # 1 hour default
```

Everything else in `cache.py` is unchanged. `DB_PATH` is now runtime-configurable: set `DB_PATH=/data/veri_cache.db` in Render dashboard if a paid persistent disk is added later.

- [ ] **Step 2: Verify nothing broke**

```bash
venv/Scripts/python -c "import cache; cache.init_db(); print('ok')"
```

Expected output: `ok` (creates `veri_cache.db` in cwd, same as before).

- [ ] **Step 3: Commit**

```bash
git add cache.py
git commit -m "feat: make SQLite DB_PATH configurable via env var for cloud deployment"
```

---

### Task 6: Fix blocking Anthropic call in `translator.py`

**Files:**
- Modify: `translator.py`

**Context:** `anthropic.Anthropic.messages.create()` is a synchronous HTTP call. When called from inside `analyze_url()` (an async function), it blocks the entire asyncio event loop for the duration of the Anthropic API response (~500ms–2s). During this block, no other Telegram messages can be processed. `AsyncAnthropic` provides a drop-in async client that integrates correctly with asyncio.

- [ ] **Step 1: Replace `translator.py` with async version**

```python
import anthropic
from config import ANTHROPIC_KEY

client = anthropic.AsyncAnthropic(api_key=ANTHROPIC_KEY)

SYSTEM = """אתה מומחה אבטחת סייבר ישראלי שתפקידו להגן על אנשים מפישינג והונאות.

כללי ברזל שאסור לך לעבור עליהם:
1. אל תגיד אף פעם "בטוח ללחוץ" או "הקישור בטוח" — אתה לא יכול להבטיח בטיחות
2. אם יש ספק כלשהו — ציין אותו. עדיף להזהיר יתר על המידה מאשר להחמיץ איום
3. אם לא נמצאו איומים, אמור "לא נמצאו איומים ידועים" — לא "בטוח"
4. קישורי מקוצרים (bit.ly, t.co וכד') הם תמיד חשודים — לעולם אל תאמר שהם בטוחים
5. אם הגעת ליעד הסופי של הקישור, כתוב מה הוא

פורמט התשובה:
🔗 **יעד הקישור:** [הדומיין הסופי שנמצא, או "לא ידוע"]
⚠️ **רמת סיכון:** גבוהה / בינונית / לא ניתן לאמת
📋 **ממצאים:** [רשום כאן רק ממצאים שליליים/חשודים שנמצאו. אם מקור מסוים לא מצא כלום — אל תזכיר אותו בכלל. המשתמש לא צריך לדעת איפה לא נמצא איום — רק איפה נמצא]
🛑 **המלצה:** [מה לעשות — ספציפי וברור. אם לא זוהה שום איום בשום מקור — חייב לציין: "אם הכניסה לאתר אינה הכרחית, עדיף להימנע"]

חוק קריטי לגבי ממצאים: אל תכתוב "לא נמצא ב-X" או "X לא זיהה איום" — שתיקה על מקור נקי היא הדרך הנכונה. רשום רק מה שנמצא בפועל.
אם הקישור הוא מקוצר ולא ניתן לאמת את היעד הסופי, כתוב זאת מפורשות."""


async def get_verdict(url: str, vt: dict, us: dict, domain: dict,
                      gsb: dict = None, pt: dict = None, op: dict = None, abuse: dict = None,
                      certil: dict = None, final_url: str = None, was_shortened: bool = False) -> str:
    shortener_note = ""
    if was_shortened:
        shortener_note = f"\n⚠️ קישור מקוצר! הקישור המקורי הוביל ל: {final_url or 'לא ידוע'}"

    gsb_line = None
    if gsb and gsb.get("available"):
        if gsb.get("threat_found"):
            gsb_line = f"איום זוהה: {', '.join(gsb.get('threat_types', []))}"

    pt_line = None
    if pt and pt.get("available"):
        if pt.get("verified"):
            pt_line = "נמצא במאגר פישינג מאומת ✓"
        elif pt.get("in_database"):
            pt_line = "נמצא במאגר פישינג (לא מאומת)"

    op_line = None
    if op and op.get("available"):
        if op.get("threat_found"):
            op_line = "נמצא ברשימת פישינג של OpenPhish ⚠️"

    certil_line = None
    if certil and certil.get("available") and certil.get("threat_found"):
        certil_line = "נמצא בהתרעות CERT-IL 🚨"

    abuse_line = None
    if abuse and abuse.get("available") and "error" not in abuse:
        score = abuse.get("abuse_score", 0)
        reports = abuse.get("total_reports", 0)
        if score > 0 or reports > 0:
            abuse_line = f"ציון ניצול לרעה: {score}/100 ({reports} דיווחים)"

    heuristic_flags = domain.get("heuristic_flags", [])

    threat_sources = []
    vt_malicious = vt.get('malicious', 0) or 0
    vt_suspicious = vt.get('suspicious', 0) or 0
    if vt_malicious > 0 or vt_suspicious > 0:
        threat_sources.append(f"VirusTotal: {vt_malicious} מנועים זדוניים, {vt_suspicious} חשודים")
    us_malicious = us.get('malicious')
    us_score = us.get('score', 0) or 0
    if us_malicious or us_score >= 50:
        tags = ', '.join(us.get('tags', [])) or 'אין'
        threat_sources.append(f"URLScan: סומן כזדוני={us_malicious}, ציון={us_score}/100, תגיות={tags}")
    if gsb_line:
        threat_sources.append(f"Google Safe Browsing: {gsb_line}")
    if pt_line:
        threat_sources.append(f"PhishTank: {pt_line}")
    if op_line:
        threat_sources.append(f"OpenPhish: {op_line}")
    if abuse_line:
        threat_sources.append(f"AbuseIPDB: {abuse_line}")
    if certil_line:
        threat_sources.append(f"CERT-IL: {certil_line}")

    domain_flags = []
    if domain.get('new_domain'):
        domain_flags.append(f"דומיין חדש מאוד — גיל: {domain.get('age_days', 'לא ידוע')} ימים")
    if domain.get('lookalike'):
        brands = ', '.join(domain.get('brands', []))
        domain_flags.append(f"חיקוי מותג ידוע: {brands}")
    if heuristic_flags:
        domain_flags.append(f"דגלים היוריסטיים ({domain.get('heuristic_score', 0)}): " + "; ".join(heuristic_flags))

    all_findings = threat_sources + domain_flags
    findings_block = "\n".join(f"- {f}" for f in all_findings) if all_findings else "לא זוהו ממצאים שליליים בשום מקור."

    no_threats_found = not all_findings

    prompt = f"""
URL מקורי: {url}
{shortener_note}
URL סופי לאחר פתיחה: {final_url or url}

ממצאים שליליים שנמצאו (בלבד):
{findings_block}

{"⚠️ שים לב: לא זוהו איומים ידועים בשום מקור. חובה לציין בהמלצה שאם הכניסה אינה הכרחית — עדיף להימנע." if no_threats_found else ""}

ספק פסיקה בעברית לפי הפורמט שקיבלת.
זכור: עדיף להזהיר יתר על המידה. לעולם אל תאמר "בטוח ללחוץ".
כלל קריטי: אל תזכיר מקורות שלא מצאו כלום — רק מה שנמצא בפועל.
"""
    msg = await client.messages.create(
        model="claude-haiku-4-5-20251001",
        max_tokens=500,
        system=SYSTEM,
        messages=[{"role": "user", "content": prompt}],
    )
    return msg.content[0].text
```

Only changes from the original:
- Line 4: `anthropic.Anthropic` → `anthropic.AsyncAnthropic`
- Line 25: `def get_verdict` → `async def get_verdict`
- Line 113: `client.messages.create` → `await client.messages.create`

- [ ] **Step 2: Verify import works**

```bash
venv/Scripts/python -c "from translator import get_verdict; print('ok')"
```

Expected: `ok`

- [ ] **Step 3: Commit**

```bash
git add translator.py
git commit -m "fix: switch Anthropic client to AsyncAnthropic to avoid blocking asyncio event loop"
```

---

### Task 7: Update `bot.py` to await `get_verdict`

**Files:**
- Modify: `bot.py`

**Context:** `get_verdict` is now `async def`. The existing call in `analyze_url()` is `return get_verdict(...)` which would return a coroutine object instead of a string. Must add `await`.

- [ ] **Step 1: Add `await` to the `get_verdict` call in `bot.py`**

In `bot.py`, find line 76 (the `return get_verdict(...)` line) and change it to:

```python
    return await get_verdict(url, vt, us, domain_info, gsb=gsb, pt=pt, op=op, abuse=abuse, certil=certil, final_url=final_url, was_shortened=shortened)
```

The full `analyze_url` function after the change:

```python
async def analyze_url(url: str) -> str:
    shortened = is_shortener(url)
    final_url = await unshorten_url(url) if shortened else url
    scan_target = final_url if final_url != url else url

    # Phase 0: pure-CPU checks — 0ms, no I/O
    lookalike  = check_lookalike(scan_target)
    heuristics = check_heuristics(scan_target)

    # Wave 1: fast network checks (~1-2s each)
    gsb, pt, op, abuse, certil = await asyncio.gather(
        google_safe_browsing(scan_target),
        phishtank_check(scan_target),
        openphish_check(scan_target),
        abuseipdb_check(scan_target),
        certil_check(scan_target),
    )

    confirmed_threat = (
        (gsb.get("available") and gsb.get("threat_found"))
        or (pt.get("available") and pt.get("verified"))
        or (op.get("available") and op.get("threat_found"))
        or (certil.get("available") and certil.get("threat_found"))
    )

    if confirmed_threat:
        vt  = {"malicious": 0, "suspicious": 0, "harmless": 0, "undetected": 0}
        us  = {}
        age = {"age_days": None, "new_domain": None}
    else:
        vt, us, age = await asyncio.gather(
            vt_scan(scan_target),
            urlscan_scan(scan_target),
            check_domain_age(scan_target),
        )

    domain_info = {**lookalike, **age, **heuristics}
    return await get_verdict(url, vt, us, domain_info, gsb=gsb, pt=pt, op=op, abuse=abuse, certil=certil, final_url=final_url, was_shortened=shortened)
```

- [ ] **Step 2: Smoke-test the import chain**

```bash
venv/Scripts/python -c "from bot import analyze_url; print('ok')"
```

Expected: `ok` (no import errors)

- [ ] **Step 3: Commit**

```bash
git add bot.py
git commit -m "fix: await async get_verdict in analyze_url"
```

---

### Task 8: Final verification

- [ ] **Step 1: Confirm all new files exist**

```bash
ls Dockerfile render.yaml .dockerignore
```

Expected: all three listed with no "No such file" error.

- [ ] **Step 2: Confirm bot.py starts without error**

```bash
venv/Scripts/python -c "
import asyncio
import os
os.environ.setdefault('TELEGRAM_TOKEN', 'dummy')
from bot import extract_urls
result = extract_urls('check https://example.com now')
assert result == ['https://example.com'], result
print('url extraction ok')
"
```

Expected: `url extraction ok`

- [ ] **Step 3: Confirm translator import chain**

```bash
venv/Scripts/python -c "
import inspect, translator
assert inspect.iscoroutinefunction(translator.get_verdict), 'get_verdict must be async'
print('translator async ok')
"
```

Expected: `translator async ok`

- [ ] **Step 4: Final commit summary**

```bash
git log --oneline -8
```

Expected: 6 new commits visible above the previous `fix: apply all 15 Israeli AppSec audit findings`.

---

## Post-Deployment Checklist (Manual — done in Render dashboard)

After pushing to GitHub:
1. Rotate all API keys (old keys are in committed git history via `.env`)
2. Create Render account → New → Background Worker → connect GitHub repo
3. Set env vars in Render dashboard: `TELEGRAM_TOKEN`, `VIRUSTOTAL_KEY`, `ANTHROPIC_KEY`, `URLSCAN_KEY`, `GOOGLE_SAFE_BROWSING_KEY`, `PHISHTANK_KEY`, `ABUSEIPDB_KEY`
4. Deploy — Render builds Dockerfile, starts `python bot.py`
5. Send `/start` to bot on Telegram to confirm it responds
