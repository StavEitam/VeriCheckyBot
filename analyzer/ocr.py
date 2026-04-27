import re
import io
import logging
from PIL import Image
import pytesseract

logger = logging.getLogger(__name__)

# Mirrors bot.py URL_RE — catches http/https, www., known-TLD bare domains, and any-TLD+path
_URL_RE = re.compile(
    r"(?:https?://|www\.)[^\s\"'<>]+"
    r"|(?<!\w)(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\."
    r"(?:co\.il|org\.il|gov\.il|net\.il|ac\.il|muni\.il"
    r"|com|net|org|io|co|info|biz|ru|xyz|top|click|link|ly|me|tv|cc|tk|ml|ga|cf|gq)"
    r"(?:/[^\s\"'<>]*)?)+"
    r"|(?<!\w)(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)"
    r"[a-zA-Z]{2,8}/[^\s\"'<>]+"
)

# PSM 11: sparse text — finds text anywhere in image, needed for chat/SMS bubble layouts
# OEM 3: LSTM neural net engine
_TESS_CONFIG = "--oem 3 --psm 11"
_MIN_WIDTH = 1200  # Tesseract accuracy drops below ~300 DPI equivalent


def _preprocess(img: Image.Image) -> Image.Image:
    w, h = img.size
    if w < _MIN_WIDTH:
        scale = _MIN_WIDTH / w
        img = img.resize((int(w * scale), int(h * scale)), Image.LANCZOS)

    img = img.convert("L")  # grayscale

    # Invert dark-mode screenshots (white text on dark background)
    pixels = list(img.getdata())
    avg_brightness = sum(pixels) / len(pixels)
    if avg_brightness < 128:
        img = img.point(lambda p: 255 - p)

    # Binarize to pure black/white — blue hyperlinks (#007AFF) become gray(154) after
    # inversion; threshold at 170 maps them to black so Tesseract reads them cleanly
    img = img.point(lambda p: 255 if p > 170 else 0)
    return img


def extract_urls_from_image(image_bytes: bytes) -> list[str]:
    img = Image.open(io.BytesIO(image_bytes))
    img = _preprocess(img)

    text = pytesseract.image_to_string(img, lang="heb+eng", config=_TESS_CONFIG)
    logger.info("[OCR] raw text: %r", text)

    urls = []
    for m in _URL_RE.finditer(text):
        val = m.group(0)
        if not val.startswith("http"):
            val = "https://" + val
        urls.append(val)

    logger.info("[OCR] extracted URLs: %s", urls)
    return urls
