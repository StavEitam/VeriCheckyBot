import asyncio
import re
import logging
from telegram import Update
from telegram.ext import ApplicationBuilder, CommandHandler, MessageHandler, filters, ContextTypes

import cache
from config import TELEGRAM_TOKEN
from analyzer.url_checker import vt_scan, urlscan_scan, unshorten_url, is_shortener, google_safe_browsing, phishtank_check, openphish_check, abuseipdb_check
from analyzer.domain_intel import check_lookalike, check_domain_age, check_heuristics
from analyzer.ocr import extract_urls_from_image
from translator import get_verdict

logging.basicConfig(level=logging.INFO)

URL_RE = re.compile(
    r"(?:https?://|www\.)[^\s\"'<>]+"                          # Branch 1: has protocol/www
    r"|(?<!\w)(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\."
    r"(?:co\.il|org\.il|gov\.il|net\.il|ac\.il|muni\.il"
    r"|com|net|org|io|co|info|biz|ru|xyz|top|click|link|ly|me|tv|cc|tk|ml|ga|cf|gq)"
    r"(?:/[^\s\"'<>]*)?)+"                                     # Branch 2: known TLD list
    r"|(?<!\w)(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)"
    r"[a-zA-Z]{2,8}/[^\s\"'<>]+"                              # Branch 3: any TLD but MUST have path
)


def extract_urls(text: str) -> list[str]:
    urls = []
    for m in URL_RE.finditer(text or ""):
        val = m.group(0)
        if not val.startswith("http"):
            val = "https://" + val
        urls.append(val)
    return urls


async def analyze_url(url: str) -> str:
    shortened = is_shortener(url)
    final_url = await unshorten_url(url) if shortened else url
    scan_target = final_url if final_url != url else url

    # Wave 1: fast checks (~1-2s each)
    gsb, pt, op, abuse = await asyncio.gather(
        google_safe_browsing(scan_target),
        phishtank_check(scan_target),
        openphish_check(scan_target),
        abuseipdb_check(scan_target),
    )
    lookalike  = check_lookalike(scan_target)
    heuristics = check_heuristics(scan_target)

    confirmed_threat = (
        (gsb.get("available") and gsb.get("threat_found"))
        or (pt.get("available") and pt.get("verified"))
        or (op.get("available") and op.get("threat_found"))
    )

    if confirmed_threat:
        # Known bad — skip slow APIs, respond immediately
        vt  = {"malicious": 0, "suspicious": 0, "harmless": 0, "undetected": 0}
        us  = {}
        age = {"age_days": None, "new_domain": None}
    else:
        # Wave 2: slow checks (15-70s) only when no confirmed threat
        vt, us, age = await asyncio.gather(
            vt_scan(scan_target),
            urlscan_scan(scan_target),
            check_domain_age(scan_target),
        )

    domain_info = {**lookalike, **age, **heuristics}
    return get_verdict(url, vt, us, domain_info, gsb=gsb, pt=pt, op=op, abuse=abuse, final_url=final_url, was_shortened=shortened)


async def start(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text(
        "שלום! אני Veri 🛡️\n\n"
        "אני בודק קישורים חשודים ומזהיר אם הם מסוכנים.\n\n"
        "איך להשתמש בי:\n"
        "• קיבלת הודעה עם קישור חשוד? פשוט העתק והדבק אותה כאן\n"
        "• יש לך צילום מסך של הודעה חשודה? שלח אותו ישירות\n\n"
        "אני אבדוק ואגיד לך אם זה בטוח או לא 🔍"
    )


async def handle_message(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    text = update.message.text or ""
    urls = extract_urls(text)

    if not urls:
        await update.message.reply_text(
            "לא מצאתי קישור בהודעה 🤔\n\n"
            "נסה להעתיק את ההודעה המלאה כפי שקיבלת אותה, כולל הקישור."
        )
        return

    await update.message.reply_text(f"בודק {len(urls)} קישור/ים... ⏳")

    for url in urls[:3]:  # cap at 3 per message
        try:
            verdict = await analyze_url(url)
            await update.message.reply_text(f"🔗 {url}\n\n{verdict}")
        except Exception as e:
            await update.message.reply_text(f"שגיאה בבדיקת {url}: {e}")


async def handle_photo(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    photo = update.message.photo[-1]
    file = await ctx.bot.get_file(photo.file_id)
    image_bytes = await file.download_as_bytearray()

    urls = extract_urls_from_image(bytes(image_bytes))
    if not urls:
        await update.message.reply_text("לא מצאתי קישורים בצילום המסך.")
        return

    await update.message.reply_text(f"זיהיתי {len(urls)} קישור/ים בתמונה. בודק... ⏳")
    for url in urls[:3]:
        try:
            verdict = await analyze_url(url)
            await update.message.reply_text(f"🔗 {url}\n\n{verdict}")
        except Exception as e:
            await update.message.reply_text(f"שגיאה בבדיקת {url}: {e}")


def main():
    cache.init_db()
    app = ApplicationBuilder().token(TELEGRAM_TOKEN).build()
    app.add_handler(CommandHandler("start", start))
    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, handle_message))
    app.add_handler(MessageHandler(filters.PHOTO, handle_photo))
    app.run_polling()


if __name__ == "__main__":
    main()
