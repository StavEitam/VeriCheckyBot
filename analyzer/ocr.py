import re
import io
from PIL import Image
import pytesseract


def extract_urls_from_image(image_bytes: bytes) -> list[str]:
    img = Image.open(io.BytesIO(image_bytes))
    text = pytesseract.image_to_string(img, lang="eng+heb")
    urls = re.findall(r"https?://[^\s\"'<>]+", text)
    return urls
