import base64
import binascii
import re
import unicodedata

# Common Cyrillic and Greek homoglyphs mapped to ASCII
HOMOGLYPH_MAP = str.maketrans({
    "а": "a", "А": "A", "е": "e", "Е": "E", "о": "o", "О": "O",
    "р": "p", "Р": "P", "с": "c", "С": "C", "у": "y", "У": "Y",
    "х": "x", "Х": "X", "і": "i", "І": "I", "к": "k", "К": "K",
    "м": "m", "М": "M", "н": "h", "Н": "H", "т": "t", "Т": "T",
    "α": "a", "Α": "A", "ε": "e", "Ε": "E", "ο": "o", "Ο": "O",
    "ρ": "p", "Ρ": "P", "τ": "t", "Τ": "T", "υ": "y", "χ": "x",
})

B64_PATTERN = re.compile(r"\b[A-Za-z0-9+/]{16,2048}={0,2}\b")
HEX_PATTERN = re.compile(r"\b(?:0x)?([0-9a-fA-F]{16,2048})\b")

MAX_DECODED_CHUNKS = 8
MAX_SCAN_LENGTH = 20000


def strip_invisible_and_fold(text: str) -> str:
    # Remove Unicode format/zero-width characters (e.g., U+200B, U+200C, U+FEFF)
    cleaned = "".join(ch for ch in text if unicodedata.category(ch) != "Cf")
    folded = unicodedata.normalize("NFKC", cleaned)
    return folded.translate(HOMOGLYPH_MAP)


def _safe_decode_chunks(text: str) -> list[str]:
    decoded_parts: list[str] = []

    for match in B64_PATTERN.finditer(text):
        if len(decoded_parts) >= MAX_DECODED_CHUNKS:
            break
        token = match.group(0)
        if len(token) % 4 != 0:
            continue
        try:
            raw = base64.b64decode(token, validate=True)
            decoded = raw.decode("utf-8", errors="ignore").strip()
            if decoded and any(c.isalpha() for c in decoded):
                decoded_parts.append(strip_invisible_and_fold(decoded))
        except (binascii.Error, ValueError):
            continue

    for match in HEX_PATTERN.finditer(text):
        if len(decoded_parts) >= MAX_DECODED_CHUNKS:
            break
        hex_str = match.group(1)
        if len(hex_str) % 2 != 0:
            continue
        try:
            raw = bytes.fromhex(hex_str)
            decoded = raw.decode("utf-8", errors="ignore").strip()
            if decoded and any(c.isalpha() for c in decoded):
                decoded_parts.append(strip_invisible_and_fold(decoded))
        except ValueError:
            continue

    return decoded_parts


def normalize_for_scan(text: str) -> str:
    """Returns normalized text plus bounded decoded payloads for guardrail scanning."""
    normalized = strip_invisible_and_fold(text)
    decoded_chunks = _safe_decode_chunks(normalized)
    if not decoded_chunks:
        return normalized
    combined = f"{normalized}\n" + "\n".join(decoded_chunks)
    return combined[:MAX_SCAN_LENGTH]
