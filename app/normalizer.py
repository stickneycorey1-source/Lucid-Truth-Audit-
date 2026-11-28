import base64
import re
import unicodedata
from typing import List
from urllib.parse import unquote

# Invisible formatting & smuggling chars: soft hyphen, CGJ, ALM, Hangul fillers,
# zero-width/BiDi controls, BOM, and Variation Selectors 1-16
INVISIBLE_RE = re.compile(
    r"[\u00ad\u034f\u061c\u115f\u1160\u180e\u200b-\u200f\u202a-\u202e\u2060-\u206f\u3164\ufe00-\ufe0f\ufeff\uffa0]"
)

# Common Cyrillic and Greek homoglyphs mapped to ASCII
HOMOGLYPH_MAP = str.maketrans({
    # Cyrillic
    "а": "a", "А": "A", "е": "e", "Е": "E", "і": "i", "І": "I",
    "ј": "j", "о": "o", "О": "O", "р": "p", "Р": "P", "с": "c",
    "С": "C", "у": "y", "У": "Y", "х": "x", "Х": "X", "ѕ": "s", "Ѕ": "S",
    # Greek
    "α": "a", "Α": "A", "ε": "e", "Ε": "E", "ι": "i", "Ι": "I",
    "κ": "k", "Κ": "K", "ν": "v", "ο": "o", "Ο": "O", "ρ": "p",
    "Ρ": "P", "τ": "t", "Τ": "T", "υ": "u", "χ": "x", "Χ": "X",
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
    normalized = token.replace("-", "+").replace("_", "/")
    rem = len(normalized) % 4
    if rem == 1:
        return ""
    if rem:
        normalized += "=" * (4 - rem)
    try:
        raw = base64.b64decode(normalized.encode("ascii"), validate=True)
        decoded = raw.decode("utf-8", errors="strict")
        if _is_mostly_printable(decoded) and any(ch.isalpha() for ch in decoded):
            return decoded
    except Exception:
        return ""
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
    Normalizes zero-width characters, soft hyphens, invisible smuggling chars,
    combining diacritics, NFKC forms, Cyrillic/Greek homoglyphs, leetspeak substitutions,
    and decodes URL-encoded, standard/unpadded/URL-safe Base64, and contiguous/0x/spaced Hex.
    """
    if not text:
        return ""

    candidates: List[str] = []
    seen: set[str] = set()

    def _add_candidate(raw_val: str) -> None:
        norm = _strip_invisibles_and_diacritics(raw_val)
        if norm and norm not in seen:
            seen.add(norm)
            candidates.append(norm)
        leet = norm.translate(LEET_MAP)
        if leet and leet not in seen:
            seen.add(leet)
            candidates.append(leet)

    _add_candidate(text)
    normalized = candidates[0] if candidates else ""

    if "%" in normalized:
        url_decoded = unquote(normalized)
        if url_decoded != normalized:
            _add_candidate(url_decoded)

    for match in EMBEDDED_B64_RE.findall(normalized):
        decoded = _try_decode_b64(match)
        if decoded:
            _add_candidate(decoded)

    for match in EMBEDDED_HEX_RE.findall(normalized):
        decoded = _try_decode_hex(match)
        if decoded:
            _add_candidate(decoded)

    for match in SPACED_HEX_RE.findall(normalized):
        decoded = _try_decode_hex(match)
        if decoded:
            _add_candidate(decoded)

    return " ".join(candidates)