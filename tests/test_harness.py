"""
Veri test harness — measure bot detection accuracy.

Modes:
  python tests/test_harness.py          # fast mode: heuristics only, no API calls
  python tests/test_harness.py --full   # full mode: real API pipeline (burns quota)

Scoring:
  TP = dangerous URL correctly flagged
  TN = clean URL correctly passed
  FP = clean URL incorrectly flagged  (false alarm)
  FN = dangerous URL missed           (worst outcome)
"""

import asyncio
import json
import sys
import os

sys.stdout.reconfigure(encoding="utf-8")
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import cache
from analyzer.domain_intel import check_lookalike, check_heuristics
from analyzer.url_checker import is_shortener

FULL_MODE = "--full" in sys.argv

PASS  = "✅"
FAIL  = "❌"
WARN  = "⚠️"
SKIP  = "⏭️"


def heuristic_verdict(url: str) -> str:
    """Fast verdict using only local logic — no API calls."""
    if is_shortener(url):
        return "suspicious"

    lookalike  = check_lookalike(url)
    heuristics = check_heuristics(url)
    score      = heuristics["heuristic_score"]
    has_brand  = lookalike["lookalike"]

    if score >= 3 or (score >= 2 and has_brand):
        return "dangerous"
    if score >= 2 or has_brand:
        return "suspicious"
    return "clean"


async def full_verdict(url: str) -> str:
    """Full verdict using real API pipeline."""
    from bot import analyze_url
    text = await analyze_url(url)
    text_lower = text.lower()
    if "גבוהה" in text or "מסוכן" in text or "פישינג" in text:
        return "dangerous"
    if "בינונית" in text or "חשוד" in text:
        return "suspicious"
    return "clean"


def score_result(expected: str, got: str) -> str:
    if expected == "dangerous":
        return "TP" if got == "dangerous" else ("FP_reverse" if got == "clean" else "FN_partial")
    if expected == "clean":
        return "TN" if got == "clean" else "FP"
    if expected == "suspicious":
        return "OK" if got in ("suspicious", "dangerous") else "FN_partial"
    return "UNKNOWN"


async def run():
    cache.init_db()
    urls_path = os.path.join(os.path.dirname(__file__), "urls.json")
    with open(urls_path, encoding="utf-8") as f:
        cases = json.load(f)

    mode_label = "FULL (API)" if FULL_MODE else "FAST (heuristics only)"
    print(f"\n{'='*60}")
    print(f"  Veri Test Harness — {mode_label}")
    print(f"  {len(cases)} test cases")
    print(f"{'='*60}\n")

    results = {"TP": 0, "TN": 0, "FP": 0, "FN": 0, "FN_partial": 0, "OK": 0}

    for case in cases:
        url      = case["url"]
        expected = case["expected"]
        category = case["category"]
        note     = case["note"]

        if FULL_MODE:
            got = await full_verdict(url)
        else:
            got = heuristic_verdict(url)

        outcome = score_result(expected, got)
        results[outcome] = results.get(outcome, 0) + 1

        if outcome == "TP":
            icon = PASS
        elif outcome == "TN":
            icon = PASS
        elif outcome == "OK":
            icon = PASS
        elif outcome in ("FN", "FN_partial", "FP_reverse"):
            icon = FAIL
        else:
            icon = WARN

        print(f"{icon} [{category}]")
        print(f"   URL:      {url}")
        print(f"   Expected: {expected} | Got: {got} | Outcome: {outcome}")
        print(f"   Note:     {note}\n")

    total   = len(cases)
    tp      = results.get("TP", 0)
    tn      = results.get("TN", 0)
    fp      = results.get("FP", 0)
    fn      = results.get("FN", 0) + results.get("FN_partial", 0) + results.get("FP_reverse", 0)
    ok      = results.get("OK", 0)
    correct = tp + tn + ok
    missed  = fn

    print(f"{'='*60}")
    print(f"  RESULTS")
    print(f"{'='*60}")
    print(f"  Total cases : {total}")
    print(f"  ✅ Correct  : {correct}  (TP={tp}, TN={tn}, suspicious-OK={ok})")
    print(f"  ❌ Wrong    : {total - correct - missed}")
    print(f"  🚨 Missed   : {missed}  (dangerous URLs not caught — worst outcome)")
    print(f"  Accuracy    : {correct/total*100:.1f}%")

    if missed > 0:
        print(f"\n  ⚠️  {missed} dangerous URL(s) not caught — review heuristics.")
    else:
        print(f"\n  🛡️  All dangerous URLs caught.")
    print(f"{'='*60}\n")


if __name__ == "__main__":
    asyncio.run(run())
