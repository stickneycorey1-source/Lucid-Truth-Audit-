from __future__ import annotations

import re
import unicodedata
from typing import Final

from pydantic import BaseModel, Field

try:
    from confusable_homoglyphs import confusables as _confusables
except ImportError:  # pragma: no cover - fallback when optional dep is absent
    _confusables = None

# Explicit Trojan Source / BiDi override codepoints (subset of Unicode Cf)
BIDI_CONTROL_CHARS: Final[frozenset[str]] = frozenset(
    {
        "\u061c",  # Arabic Letter Mark
        "\u200e",  # Left-to-Right Mark
        "\u200f",  # Right-to-Left Mark
        "\u202a",  # Left-to-Right Embedding
        "\u202b",  # Right-to-Left Embedding
        "\u202c",  # Pop Directional Formatting
        "\u202d",  # Left-to-Right Override
        "\u202e",  # Right-to-Left Override (Primary Trojan Source vector)
        "\u2066",  # Left-to-Right Isolate
        "\u2067",  # Right-to-Left Isolate
        "\u2068",  # First Strong Isolate
        "\u2069",  # Pop Directional Isolate
    }
)

# Safe whitespace control characters to preserve
SAFE_CONTROL_CHARS: Final[frozenset[str]] = frozenset({"\t", "\n", "\r"})

# Tokenizer for word-level UTS #39 inspection
TOKEN_PATTERN: Final[re.Pattern[str]] = re.compile(r"\S+")

# Built-in fallback table of high-risk Cyrillic/Greek Latin-confusable codepoints
FALLBACK_CONFUSABLES: Final[dict[str, str]] = {
    "\u0410": "CYRILLIC",  # А -> A
    "\u0412": "CYRILLIC",  # В -> B
    "\u0421": "CYRILLIC",  # С -> C
    "\u0415": "CYRILLIC",  # Е -> E
    "\u041d": "CYRILLIC",  # Н -> H
    "\u0406": "CYRILLIC",  # І -> I
    "\u041a": "CYRILLIC",  # К -> K
    "\u041c": "CYRILLIC",  # М -> M
    "\u041e": "CYRILLIC",  # О -> O
    "\u0420": "CYRILLIC",  # Р -> P
    "\u0422": "CYRILLIC",  # Т -> T
    "\u0425": "CYRILLIC",  # Х -> X
    "\u0430": "CYRILLIC",  # а -> a
    "\u0441": "CYRILLIC",  # с -> c
    "\u0435": "CYRILLIC",  # е -> e
    "\u0456": "CYRILLIC",  # і -> i
    "\u0458": "CYRILLIC",  # ј -> j
    "\u043e": "CYRILLIC",  # о -> o
    "\u0440": "CYRILLIC",  # р -> p
    "\u0455": "CYRILLIC",  # ѕ -> s
    "\u0445": "CYRILLIC",  # х -> x
    "\u0443": "CYRILLIC",  # у -> y
    "\u0391": "GREEK",     # Α -> A
    "\u0392": "GREEK",     # Β -> B
    "\u0395": "GREEK",     # Ε -> E
    "\u0396": "GREEK",     # Ζ -> Z
    "\u0397": "GREEK",     # Η -> H
    "\u0399": "GREEK",     # Ι -> I
    "\u039a": "GREEK",     # Κ -> K
    "\u039c": "GREEK",     # Μ -> M
    "\u039d": "GREEK",     # Ν -> N
    "\u039f": "GREEK",     # Ο -> O
    "\u03a1": "GREEK",     # Ρ -> P
    "\u03a4": "GREEK",     # Τ -> T
    "\u03a7": "GREEK",     # Χ -> X
    "\u03bf": "GREEK",     # ο -> o
}


def _fallback_detect_homoglyphs(
    token: str, token_index: int, preferred_aliases: list[str]
) -> list[HomoglyphFinding]:
    """Stdlib-only fallback detector when confusable-homoglyphs is not installed."""
    scripts_in_token: set[str] = set()
    for ch in token:
        if ch.isalpha():
            name = unicodedata.name(ch, "")
            if "LATIN" in name:
                scripts_in_token.add("LATIN")
            elif "CYRILLIC" in name:
                scripts_in_token.add("CYRILLIC")
            elif "GREEK" in name:
                scripts_in_token.add("GREEK")

    is_mixed = len(scripts_in_token) > 1
    findings: list[HomoglyphFinding] = []
    for ch in token:
        alias = FALLBACK_CONFUSABLES.get(ch)
        if alias and alias not in preferred_aliases:
            findings.append(
                HomoglyphFinding(
                    token_index=token_index,
                    codepoint=f"U+{ord(ch):04X}",
                    script_alias=alias,
                    is_mixed_script=is_mixed,
                )
            )
    return findings


class HomoglyphFinding(BaseModel):
    """Zero-retention metadata for a detected UTS #39 confusable character."""

    token_index: int = Field(..., description="0-based index of the offending token.")
    codepoint: str = Field(..., description="Unicode codepoint (e.g., U+0430).")
    script_alias: str = Field(..., description="Detected Unicode script alias.")
    is_mixed_script: bool = Field(
        ..., description="True if the token mixes scripts (high spoofing risk)."
    )


class SanitizationResult(BaseModel):
    """Structured output returned by the sanitization pipeline."""

    sanitized_text: str
    was_modified: bool
    stripped_cf_count: int = 0
    stripped_cc_count: int = 0
    bidi_override_detected: bool = False
    nfkc_changed: bool = False
    homoglyphs_detected: bool = False
    homoglyph_findings: list[HomoglyphFinding] = Field(default_factory=list)
    risk_flags: list[str] = Field(default_factory=list)


class InputSanitizer:
    """
    Deterministic Unicode sanitization and UTS #39 homoglyph detection engine
    for Lucid-Truth-Audit.
    """

    def __init__(self, preferred_aliases: list[str] | None = None) -> None:
        self.preferred_aliases: list[str] = preferred_aliases or ["LATIN"]

    def sanitize(self, text: str) -> SanitizationResult:
        if not text:
            return SanitizationResult(sanitized_text="", was_modified=False)

        # Stage 1: Strip Unicode Cf (Format/BiDi) and dangerous Cc (Control) chars
        cleaned_chars: list[str] = []
        stripped_cf = 0
        stripped_cc = 0
        bidi_detected = False

        for ch in text:
            if ch in BIDI_CONTROL_CHARS:
                bidi_detected = True
                stripped_cf += 1
                continue

            category = unicodedata.category(ch)
            if category == "Cf":
                stripped_cf += 1
                continue
            if category == "Cc" and ch not in SAFE_CONTROL_CHARS:
                stripped_cc += 1
                continue

            cleaned_chars.append(ch)

        stage1_text = "".join(cleaned_chars)

        # Stage 2: NFKC Normalization (collapses full-width, ligatures, superscripts)
        normalized_text = unicodedata.normalize("NFKC", stage1_text)
        nfkc_changed = normalized_text != stage1_text

        # Stage 3: UTS #39 Homoglyph & Mixed-Script Detection (token-level)
        findings: list[HomoglyphFinding] = []
        for idx, match in enumerate(TOKEN_PATTERN.finditer(normalized_text)):
            token = match.group(0)
            if _confusables is not None:
                is_mixed = bool(_confusables.is_dangerous(token))
                confusable_hits = _confusables.is_confusable(
                    token,
                    greedy=True,
                    preferred_aliases=self.preferred_aliases,
                )
                if confusable_hits:
                    for hit in confusable_hits:
                        char = hit["character"]
                        findings.append(
                            HomoglyphFinding(
                                token_index=idx,
                                codepoint=f"U+{ord(char):04X}",
                                script_alias=hit.get("alias", "UNKNOWN"),
                                is_mixed_script=is_mixed,
                            )
                        )
            else:
                findings.extend(
                    _fallback_detect_homoglyphs(token, idx, self.preferred_aliases)
                )

        # Build deterministic risk flags for audit logging (no raw PII stored)
        risk_flags: list[str] = []
        if bidi_detected:
            risk_flags.append("BIDI_OVERRIDE")
        if stripped_cf > 0 and not bidi_detected:
            risk_flags.append("INVISIBLE_FORMAT_OBFUSCATION")
        if stripped_cc > 0:
            risk_flags.append("CONTROL_CHAR_INJECTION")
        if nfkc_changed:
            risk_flags.append("NFKC_COMPATIBILITY_NORMALIZED")
        if findings:
            if any(f.is_mixed_script for f in findings):
                risk_flags.append("MIXED_SCRIPT_HOMOGLYPH")
            else:
                risk_flags.append("NON_LATIN_CONFUSABLE")

        return SanitizationResult(
            sanitized_text=normalized_text,
            was_modified=(normalized_text != text),
            stripped_cf_count=stripped_cf,
            stripped_cc_count=stripped_cc,
            bidi_override_detected=bidi_detected,
            nfkc_changed=nfkc_changed,
            homoglyphs_detected=bool(findings),
            homoglyph_findings=findings,
            risk_flags=risk_flags,
        )
