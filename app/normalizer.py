import re
import base64
import unicodedata
from typing import List

# Invisible formatting chars including zero-width spaces, directional marks, BOM, and soft hyphens (U+00AD)
INVISIBLE_RE = re.compile(r"[\u00ad\u034f\u180e\u200b-\u200f\u202a-\u202e\u2060-\u206f\ufeff]")

# Common Cyrillic and Greek homoglyphs mapped to ASCII
HOMOGLYPH_MAP = str.maketrans({
    "а": "a", "А": "A", "е": "e", "Е": "E", "і": "i", "І": "I",
    "о": "o", "О": "O", "р": "p", "Р": "P", "с": "c", "С": "C",
    "у": "y", "У": "Y", "х": "x", "Х": "X", "ѕ": "s", "Ѕ": "S",
    "α": "a", "ε": "e", "ο": "o", "ρ": "p", "χ": "x",
})

LEET_MAP = str.maketrans({
    "0": "o", "1": "i", "3": "e", "4": "a", "5": "s", "7": "t", "@": "a", "$": "s", "!": "i",
})

# Matches standard & URL-safe Base64 (padded or unpadded, >= 16 chars)
EMBEDDED_B64_RE = re.compile(r"(?<![A-Za-z0-9+/_=-])[A-Za-z0-9+/_-]{16,}={0,2}(?![A-Za-z0-9+/_=-])")
# Matches contiguous Hex (>= 20 hex chars) and space-separated Hex (>= 10 byte pairs)
EMBEDDED_HEX_RE = re.compile(r"(?<![0-9a-fA-F])(?:0x)?(?:[0-9a-fA-F]{2}){10,}(?![0-9a-fA-F])")
SPACED_HEX_RE = re.compile(r"(?<![0-9a-fA-F])(?:[0-9a-fA-F]{2}\s+){9,}[0-9a-fA-F]{2}(?![0-9a-fA-F])")


def _strip_invisibles_and_diacritics(text: str) -> str:
    cleaned = INVISIBLE_RE.sub("", text)
    # Decompose combining marks (NFD) and drop non-spacing marks (category Mn)
    decomposed = unicodedata.normalize("NFD", cleaned)
    no_marks = "".join(ch for ch in decomposed if unicodedata.category(ch) != "Mn")
    return unicodedata.normalize("NFKC", no_marks).translate(HOMOGLYPH_MAP)


def _is_mostly_printable(decoded: str) -> bool:
    if not decoded:
        return False
    printable = sum(32 <= ord(c) <= 126 or c in "\n\r\t" for c in decoded)
    return (printable / len(decoded)) >= 0.85


def _try_decode_b64(token: str) -> str:
    # Reject pure lowercase words that resemble base64
    if token.isalpha() and token.islower():
        return ""
    padded = token + ("=" * ((4 - len(token) % 4) % 4))
    for decoder in (base64.b64decode, base64.urlsafe_b64decode):
        try:
            raw = decoder(padded.encode("ascii"))
            decoded = raw.decode("utf-8", errors="strict")
            if _is_mostly_printable(decoded) and any(ch.isalpha() for ch in decoded):
                return decoded
        except Exception:
            continue
    return ""


def _try_decode_hex(token: str) -> str:
    compact = re.sub(r"^0x|\s+", "", token, flags=re.IGNORECASE)
    if len(compact) % 2 != 0:
        return ""
    try:
        raw = bytes.fromhex(compact)
        decoded = raw.decode("utf-8", errors="strict")
        return decoded if _is_mostly_printable(decoded) else ""
    except Exception:
        return ""


def normalize_text_for_inspection(text: str) -> str:
    """
    Normalizes zero-width characters, soft hyphens, combining diacritics, NFKC forms,
    Cyrillic/Greek homoglyphs, leetspeak substitutions, and decodes standard, unpadded,
    or URL-safe Base64 as well as contiguous/0x/spaced Hex tokens embedded in prose.
    """
    if not text:
        return ""
    normalized = _strip_invisibles_and_diacritics(text)
    candidates: List[str] = [normalized]

    leet_folded = normalized.translate(LEET_MAP)
    if leet_folded != normalized:
        candidates.append(leet_folded)

    for match in EMBEDDED_B64_RE.findall(normalized):
        decoded = _try_decode_b64(match)
        if decoded:
            dec_norm = _strip_invisibles_and_diacritics(decoded)
            candidates.append(dec_norm)
            dec_leet = dec_norm.translate(LEET_MAP)
            if dec_leet != dec_norm:
                candidates.append(dec_leet)

    for match in EMBEDDED_HEX_RE.findall(normalized):
        decoded = _try_decode_hex(match)
        if decoded:
            candidates.append(_strip_invisibles_and_diacritics(decoded))

    for match in SPACED_HEX_RE.findall(normalized):
        decoded = _try_decode_hex(match)
        if decoded:
            candidates.append(_strip_invisibles_and_diacritics(decoded))

    return " ".join(candidates)
