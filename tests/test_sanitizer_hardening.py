"""Unit tests covering hardening changes and fallback/confusable branches in app/core/sanitizer.py."""

from __future__ import annotations

from types import SimpleNamespace

import pytest

import app.core.sanitizer as sanitizer_mod
from app.core.sanitizer import InputSanitizer


# ---------------------------------------------------------------------------
# 1. Empty input, safe whitespace, and control character stripping
# ---------------------------------------------------------------------------


def test_empty_input_returns_unmodified() -> None:
    res = InputSanitizer().sanitize("")
    assert res.sanitized_text == ""
    assert res.was_modified is False
    assert res.risk_flags == []


def test_strips_dangerous_control_chars_while_preserving_safe_whitespace() -> None:
    raw = "line1\tcol2\nline2\r\x00\x07end"
    res = InputSanitizer().sanitize(raw)

    assert res.sanitized_text == "line1\tcol2\nline2\rend"
    assert res.was_modified is True
    assert res.stripped_cc_count == 2
    assert "CONTROL_CHAR_INJECTION" in res.risk_flags


# ---------------------------------------------------------------------------
# 2. Combined BiDi + invisible format chars emit BOTH risk flags
# ---------------------------------------------------------------------------


def test_bidi_and_zero_width_emit_both_flags() -> None:
    # \u202e (RLO BiDi override) + \u200b (Zero-Width Space, non-BiDi Cf)
    raw = "pay\u202e\u200bpal"
    res = InputSanitizer().sanitize(raw)

    assert res.sanitized_text == "paypal"
    assert res.was_modified is True
    assert res.bidi_override_detected is True
    assert res.stripped_cf_count == 2
    assert "BIDI_OVERRIDE" in res.risk_flags
    assert "INVISIBLE_FORMAT_OBFUSCATION" in res.risk_flags


def test_bidi_only_does_not_emit_invisible_format_flag() -> None:
    res = InputSanitizer().sanitize("safe\u202etext")
    assert res.sanitized_text == "safetext"
    assert res.bidi_override_detected is True
    assert "BIDI_OVERRIDE" in res.risk_flags
    assert "INVISIBLE_FORMAT_OBFUSCATION" not in res.risk_flags


# ---------------------------------------------------------------------------
# 3. Invisible non-Cf smuggling characters (CGJ, Hangul filler, Variation Selector)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "smuggled,expected",
    [
        ("ig\u034fnore", "ignore"),      # Combining Grapheme Joiner (Mn)
        ("ad\u3164min", "admin"),       # Hangul Filler (Lo)
        ("key\ufe0fword", "keyword"),   # Variation Selector-16 (Mn)
    ],
)
def test_invisible_smuggling_chars_stripped_and_flagged(
    smuggled: str, expected: str
) -> None:
    res = InputSanitizer().sanitize(smuggled)
    assert res.sanitized_text == expected
    assert res.was_modified is True
    assert res.stripped_cf_count == 1
    assert res.bidi_override_detected is False
    assert "INVISIBLE_FORMAT_OBFUSCATION" in res.risk_flags


# ---------------------------------------------------------------------------
# 4. NFKC compatibility normalization
# ---------------------------------------------------------------------------


def test_nfkc_normalization_collapses_fullwidth_and_ligatures() -> None:
    res = InputSanitizer().sanitize("\uff41\uff42\uff43 \ufb01le")
    assert res.sanitized_text == "abc file"
    assert res.nfkc_changed is True
    assert "NFKC_COMPATIBILITY_NORMALIZED" in res.risk_flags


# ---------------------------------------------------------------------------
# 5. preferred_aliases normalization
# ---------------------------------------------------------------------------


def test_preferred_aliases_normalized_to_uppercase_with_latin_default() -> None:
    assert InputSanitizer([" latin ", "cyrillic"]).preferred_aliases == ["LATIN", "CYRILLIC"]
    assert InputSanitizer([]).preferred_aliases == ["LATIN"]
    assert InputSanitizer(["   "]).preferred_aliases == ["LATIN"]


# ---------------------------------------------------------------------------
# 6. Fallback homoglyph detector (lowercase Greek + Cyrillic + mixed-script)
# ---------------------------------------------------------------------------


def test_fallback_detects_mixed_script_cyrillic_and_lowercase_greek(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(sanitizer_mod, "_confusables", None)

    # Token 0: Latin + Cyrillic 'а' (\u0430) -> mixed script
    # Token 1: Latin + lowercase Greek 'α' (\u03b1) and 'ρ' (\u03c1) -> mixed script
    res = InputSanitizer().sanitize("p\u0430ypal \u03b1dmin\u03c1")

    assert res.homoglyphs_detected is True
    assert "MIXED_SCRIPT_HOMOGLYPH" in res.risk_flags
    codepoints = {f.codepoint for f in res.homoglyph_findings}
    assert {"U+0430", "U+03B1", "U+03C1"}.issubset(codepoints)
    assert all(f.is_mixed_script is True for f in res.homoglyph_findings)


def test_fallback_detects_pure_non_latin_confusable_and_respects_preferred_aliases(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(sanitizer_mod, "_confusables", None)

    # Pure lowercase Greek token -> NON_LATIN_CONFUSABLE (not mixed script)
    res_greek = InputSanitizer().sanitize("\u03b1\u03bf\u03c1")
    assert res_greek.homoglyphs_detected is True
    assert "NON_LATIN_CONFUSABLE" in res_greek.risk_flags
    assert "MIXED_SCRIPT_HOMOGLYPH" not in res_greek.risk_flags
    assert all(f.is_mixed_script is False for f in res_greek.homoglyph_findings)

    # Allowing GREEK (even in lowercase) suppresses Greek findings
    res_allowed = InputSanitizer(preferred_aliases=["latin", "greek"]).sanitize("\u03b1\u03bf\u03c1")
    assert res_allowed.homoglyphs_detected is False
    assert res_allowed.homoglyph_findings == []


# ---------------------------------------------------------------------------
# 7. External confusable_homoglyphs branch
# ---------------------------------------------------------------------------


def test_confusables_library_branch_records_findings(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fake_confusables = SimpleNamespace(
        is_dangerous=lambda token: "\u0430" in token,
        is_confusable=lambda token, greedy, preferred_aliases: (
            [{"character": "\u0430", "alias": "CYRILLIC"}] if "\u0430" in token else False
        ),
    )
    monkeypatch.setattr(sanitizer_mod, "_confusables", fake_confusables)

    res = InputSanitizer().sanitize("hello p\u0430ypal")
    assert res.homoglyphs_detected is True
    assert "MIXED_SCRIPT_HOMOGLYPH" in res.risk_flags
    assert len(res.homoglyph_findings) == 1
    finding = res.homoglyph_findings[0]
    assert finding.token_index == 1
    assert finding.codepoint == "U+0430"
    assert finding.script_alias == "CYRILLIC"
    assert finding.is_mixed_script is True