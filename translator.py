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
📋 **ממצאים:** [2-3 שורות קצרות עם מה שנמצא]
🛑 **המלצה:** [מה לעשות — ספציפי וברור]

אם הקישור הוא מקוצר ולא ניתן לאמת את היעד הסופי, כתוב זאת מפורשות."""


def get_verdict(url: str, vt: dict, us: dict, domain: dict,
                gsb: dict = None, pt: dict = None, op: dict = None, abuse: dict = None,
                final_url: str = None, was_shortened: bool = False) -> str:
    shortener_note = ""
    if was_shortened:
        shortener_note = f"\n⚠️ קישור מקוצר! הקישור המקורי הוביל ל: {final_url or 'לא ידוע'}"

    gsb_line = "לא זמין (ללא מפתח API)"
    if gsb and gsb.get("available"):
        gsb_line = f"איום זוהה: {', '.join(gsb.get('threat_types', []))}" if gsb.get("threat_found") else "לא נמצא באיומים ידועים"

    pt_line = "לא זמין (ללא מפתח API)"
    if pt and pt.get("available"):
        pt_line = "נמצא במאגר פישינג מאומת ✓" if pt.get("verified") else ("נמצא במאגר פישינג" if pt.get("in_database") else "לא נמצא במאגר")

    op_line = "לא זמין"
    if op and op.get("available"):
        op_line = "נמצא ברשימת פישינג של OpenPhish ⚠️" if op.get("threat_found") else "לא נמצא ברשימה"

    abuse_line = "לא זמין (ללא מפתח API)"
    if abuse and abuse.get("available"):
        score = abuse.get("abuse_score", 0)
        reports = abuse.get("total_reports", 0)
        if "error" in abuse:
            abuse_line = "שגיאה בבדיקה"
        else:
            abuse_line = f"ציון ניצול לרעה: {score}/100 ({reports} דיווחים)"

    heuristic_flags = domain.get("heuristic_flags", [])
    heuristics_line = "\n".join(f"  - {f}" for f in heuristic_flags) if heuristic_flags else "  אין דגלים"

    prompt = f"""
URL מקורי: {url}
{shortener_note}
URL סופי לאחר פתיחה: {final_url or url}

VirusTotal (על ה-URL הסופי):
- זדוני: {vt.get('malicious', '?')} מנועי סריקה
- חשוד: {vt.get('suspicious', '?')} מנועי סריקה
- נקי: {vt.get('harmless', '?')} מנועי סריקה

URLScan:
- URL סופי שזוהה: {us.get('final_url', final_url or url)}
- סומן כזדוני: {us.get('malicious', '?')}
- ציון סיכון: {us.get('score', '?')}/100
- תגיות: {', '.join(us.get('tags', [])) or 'אין'}

Google Safe Browsing: {gsb_line}
PhishTank: {pt_line}
OpenPhish: {op_line}
AbuseIPDB: {abuse_line}

מידע דומיין:
- גיל דומיין (ימים): {domain.get('age_days', 'לא ידוע')}
- דומיין חדש מאוד (<30 יום): {domain.get('new_domain', 'לא ידוע')}
- חיקוי מותג ידוע: {domain.get('lookalike', False)}
- מותגים שמחקים: {', '.join(domain.get('brands', [])) or 'אין'}

ניתוח היוריסטי ({domain.get('heuristic_score', 0)} דגלים):
{heuristics_line}

ספק פסיקה בעברית לפי הפורמט שקיבלת.
זכור: עדיף להזהיר יתר על המידה. לעולם אל תאמר "בטוח ללחוץ".
"""
    msg = client.messages.create(
        model="claude-haiku-4-5-20251001",
        max_tokens=500,
        system=SYSTEM,
        messages=[{"role": "user", "content": prompt}],
    )
    return msg.content[0].text
