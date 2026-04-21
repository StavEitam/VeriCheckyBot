"""Unit tests for domain_intel and url_checker — no network, no API calls."""
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import pytest
from analyzer.domain_intel import check_heuristics, check_lookalike, _registered_domain


# ── _registered_domain ──────────────────────────────────────────────────────

def test_registered_domain_standard_com():
    sub, root = _registered_domain("www.google.com")
    assert root == "google.com"
    assert sub  == "www"

def test_registered_domain_co_il():
    sub, root = _registered_domain("www.bankhapoalim.co.il")
    assert root == "bankhapoalim.co.il"
    assert sub  == "www"

def test_registered_domain_gov_il():
    sub, root = _registered_domain("misim.gov.il")
    assert root == "misim.gov.il"
    assert sub  == ""

def test_registered_domain_subdomain_co_il():
    sub, root = _registered_domain("paypal.attacker.co.il")
    assert root == "attacker.co.il"
    assert sub  == "paypal"

def test_registered_domain_org_il():
    sub, root = _registered_domain("donate.clalit.org.il")
    assert root == "clalit.org.il"
    assert sub  == "donate"

def test_registered_domain_bare_co_il():
    sub, root = _registered_domain("bankhapoalim.co.il")
    assert root == "bankhapoalim.co.il"
    assert sub  == ""


# ── check_heuristics: brand-in-subdomain — no false positive on .co.il ──────

def test_no_false_positive_bankhapoalim_co_il():
    result = check_heuristics("https://www.bankhapoalim.co.il")
    brand_flags = [f for f in result["heuristic_flags"] if "תת-דומיין" in f]
    assert brand_flags == [], f"False positive on bankhapoalim.co.il: {brand_flags}"

def test_no_false_positive_max_co_il():
    result = check_heuristics("https://www.max.co.il")
    brand_flags = [f for f in result["heuristic_flags"] if "תת-דומיין" in f]
    assert brand_flags == [], f"False positive on max.co.il: {brand_flags}"

def test_no_false_positive_clalit_org_il():
    result = check_heuristics("https://www.clalit.org.il")
    brand_flags = [f for f in result["heuristic_flags"] if "תת-דומיין" in f]
    assert brand_flags == [], f"False positive on clalit.org.il: {brand_flags}"

def test_detects_brand_in_real_subdomain_com():
    result = check_heuristics("https://paypal.evil-attacker.com")
    brand_flags = [f for f in result["heuristic_flags"] if "תת-דומיין" in f]
    assert len(brand_flags) >= 1, "paypal in subdomain of .com should be flagged"

def test_detects_brand_in_subdomain_co_il_phishing():
    result = check_heuristics("https://paypal.evil-attacker.co.il")
    brand_flags = [f for f in result["heuristic_flags"] if "תת-דומיין" in f]
    assert len(brand_flags) >= 1, "paypal in subdomain of phishing .co.il should be flagged"


# ── check_heuristics: Hebrew keyword URL-decode ──────────────────────────────

def test_hebrew_keyword_plain():
    result = check_heuristics("https://evil.xyz/כניסה")
    keyword_flags = [f for f in result["heuristic_flags"] if "כניסה" in f]
    assert len(keyword_flags) >= 1

def test_hebrew_keyword_percent_encoded():
    # %D7%9B%D7%A0%D7%99%D7%A1%D7%94 = "כניסה" (login)
    result = check_heuristics("https://evil.xyz/%D7%9B%D7%A0%D7%99%D7%A1%D7%94")
    keyword_flags = [f for f in result["heuristic_flags"] if "כניסה" in f]
    assert len(keyword_flags) >= 1, "Hebrew keyword missed in percent-encoded URL"

def test_hebrew_payment_percent_encoded():
    # %D7%AA%D7%A9%D7%9C%D7%95%D7%9D = "תשלום" (payment)
    result = check_heuristics("https://btl.co.il-update.xyz/%D7%AA%D7%A9%D7%9C%D7%95%D7%9D")
    keyword_flags = [f for f in result["heuristic_flags"] if "תשלום" in f]
    assert len(keyword_flags) >= 1, "Hebrew 'תשלום' missed in percent-encoded URL"

def test_english_keyword_still_works():
    result = check_heuristics("https://evil.xyz/login?user=foo")
    keyword_flags = [f for f in result["heuristic_flags"] if "login" in f]
    assert len(keyword_flags) >= 1


# ── check_domain_age: timeout (async) ────────────────────────────────────────

import asyncio
from analyzer.domain_intel import check_domain_age

def test_domain_age_returns_gracefully_on_bad_domain():
    result = asyncio.run(check_domain_age("https://this-does-not-exist-xyzxyz123.co.il"))
    assert isinstance(result, dict)
    assert "age_days"   in result
    assert "new_domain" in result

def test_domain_age_completes_within_12s():
    import time
    start = time.time()
    asyncio.run(check_domain_age("https://nonexistent-fake-abc999.co.il"))
    elapsed = time.time() - start
    assert elapsed < 12, f"WHOIS took {elapsed:.1f}s — timeout guard not working"


# ── GSB TTL constants ─────────────────────────────────────────────────────────

def test_gsb_ttl_constants_exist():
    import analyzer.url_checker as uc
    assert hasattr(uc, "GSB_CLEAN_TTL"),  "GSB_CLEAN_TTL missing"
    assert hasattr(uc, "GSB_THREAT_TTL"), "GSB_THREAT_TTL missing"
    assert uc.GSB_CLEAN_TTL  <= 900,  f"Clean TTL too long: {uc.GSB_CLEAN_TTL}"
    assert uc.GSB_THREAT_TTL >= 3600, f"Threat TTL too short: {uc.GSB_THREAT_TTL}"


# ── Brand false-positive whitelist ───────────────────────────────────────────

def test_no_false_positive_bit_co_il():
    result = check_lookalike("https://www.bit.co.il")
    assert not result["lookalike"], "'bit.co.il' must not be flagged as lookalike"

def test_no_false_positive_max_co_il_lookalike():
    result = check_lookalike("https://max.co.il/credit")
    assert not result["lookalike"], "'max.co.il' must not be flagged as lookalike"

def test_no_false_positive_hot_co_il():
    result = check_lookalike("https://hot.co.il")
    assert not result["lookalike"], "'hot.co.il' must not be flagged as lookalike"

def test_genuine_lookalike_still_detected():
    result = check_lookalike("https://paypa1.com")
    assert result["lookalike"], "paypa1.com should still be detected as lookalike"
    assert "paypal" in result["brands"]


# ── Punycode / IDN homoglyph — no crash ──────────────────────────────────────

def test_punycode_does_not_crash():
    result = check_lookalike("https://xn--invalid-punycode--.com")
    assert isinstance(result, dict)
    assert "lookalike" in result

def test_non_ascii_domain_does_not_crash():
    result = check_lookalike("https://www.paypaál.com")
    assert isinstance(result, dict)


# ── Weighted heuristic scoring ────────────────────────────────────────────────

def test_ip_as_domain_scores_high():
    result = check_heuristics("http://192.168.1.1/login")
    # IP=5pts + keyword "login"=1pt → ≥6
    assert result["heuristic_score"] >= 6

def test_sms_pattern_scores_high():
    result = check_heuristics("https://israelpost.co.il-track.xyz")
    # .co.il- pattern = 4pts
    assert result["heuristic_score"] >= 4

def test_score_keys_exist():
    result = check_heuristics("https://example.com")
    assert "heuristic_score" in result
    assert "heuristic_flags" in result


# ── Shortener detection ───────────────────────────────────────────────────────

def test_missing_shorteners_detected():
    from analyzer.url_checker import is_shortener
    assert is_shortener("https://bit.do/abc123"),  "bit.do not in shorteners"
    assert is_shortener("https://t2m.io/abc"),     "t2m.io not in shorteners"
    assert is_shortener("https://short.gy/abc"),   "short.gy not in shorteners"
    assert is_shortener("https://v.ht/abc"),       "v.ht not in shorteners"

def test_existing_shorteners_still_work():
    from analyzer.url_checker import is_shortener
    assert is_shortener("https://did.li/abc")
    assert is_shortener("https://bit.ly/abc")


# ── gov.il fast-pass ──────────────────────────────────────────────────────────

def test_gov_il_not_flagged_as_lookalike():
    result = check_lookalike("https://misim.gov.il/login")
    assert not result["lookalike"], "misim.gov.il must not be a lookalike"

def test_taxes_gov_il_not_flagged():
    result = check_lookalike("https://www.taxes.gov.il")
    assert not result["lookalike"], "taxes.gov.il must not be a lookalike"
