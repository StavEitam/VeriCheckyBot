import anthropic
from config import ANTHROPIC_KEY

client = anthropic.Anthropic(api_key=ANTHROPIC_KEY)

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


def get_verdict(url: str, vt: dict, us: dict, domain: dict,
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

    # Build threat-source lines — only include sources that found something
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

    # Domain-level risk signals
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
    msg = client.messages.create(
        model="claude-haiku-4-5-20251001",
        max_tokens=500,
        system=SYSTEM,
        messages=[{"role": "user", "content": prompt}],
    )
    return msg.content[0].text
