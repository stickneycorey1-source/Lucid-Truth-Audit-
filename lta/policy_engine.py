"""YAML Policy-Pack Engine for Lucid-Truth-Audit Enterprise (Hardened v2.4).

Handles:
1. Unicode NFKD diacritic stripping, NFKC normalization, zero-width stripping,
   Cyrillic + Greek homoglyph folding, whitespace collapsing, and punctuation-stripped scan
2. Bounded recursive decoding (depth=2) for URL, Base64, and Hex payloads (including punct-stripped)
3. Prompt injection & social-engineering pretext blocking (hardened benign-allow & exfil verb guard)
4. Flooding / high-entropy gibberish defense
5. PII / PHI / PCI detection and deterministic redaction (including Luhn PAN check)
6. Industry-specific domain guardrails with strict finite-numeric validation (blocks NaN/Inf/str)
7. Symmetric output-boundary leak prevention on both raw and canonicalized outputs
"""

from __future__ import annotations

import base64
import math
import re
import unicodedata
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import unquote

import yaml

ZERO_WIDTH_RE = re.compile(r"[\u200b\u200c\u200d\u2060\ufeff\u00ad]")
WHITESPACE_RE = re.compile(r"\s+")
PUNCT_STRIP_RE = re.compile(r"[^\w\s]")
EXFIL_ACTION_RE = re.compile(
    r"\b(?:reveal|dump|print|show|output|ignore|override|bypass|leak|verbatim|disclose|expose|repeat)\b"
)
SYSTEM_PROMPT_EXFIL_RE = re.compile(
    r"\b(?:reveal|dump|print|show|output|leak|disclose|expose|repeat)\b.{0,35}\b(?:system prompt|hidden instructions|developer prompt)\b"
)
HOMOGLYPH_MAP = str.maketrans(
    {
        # Cyrillic lookalikes
        "\u0430": "a",
        "\u0435": "e",
        "\u043e": "o",
        "\u0440": "p",
        "\u0441": "c",
        "\u0443": "y",
        "\u0445": "x",
        "\u0456": "i",
        "\u0410": "a",
        "\u0415": "e",
        "\u041e": "o",
        "\u0420": "p",
        "\u0421": "c",
        "\u0423": "y",
        "\u0425": "x",
        # Greek lookalikes
        "\u03b1": "a",
        "\u03b5": "e",
        "\u03bf": "o",
        "\u03c1": "p",
        "\u03b9": "i",
        "\u03ba": "k",
        "\u03bd": "v",
        "\u03c4": "t",
        "\u03c5": "u",
        "\u03c7": "x",
        "\u0391": "a",
        "\u0395": "e",
        "\u039f": "o",
        "\u03a1": "p",
        "\u0399": "i",
        "\u039a": "k",
        "\u03a4": "t",
        "\u03a7": "x",
    }
)

BASE64_CANDIDATE_RE = re.compile(
    r"(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{20,}={0,2}(?![A-Za-z0-9+/=])"
)
HEX_CANDIDATE_RE = re.compile(r"\b(?:0x)?[0-9a-fA-F]{24,}\b")

SSN_RE = re.compile(r"\b\d{3}-\d{2}-\d{4}\b")
EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
PHONE_RE = re.compile(r"\b(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b")
PAN_CANDIDATE_RE = re.compile(r"\b(?:\d[ -]*?){13,19}\b")
API_SECRET_RE = re.compile(
    r"\b(?:sk-[A-Za-z0-9]{16,}|ghp_[A-Za-z0-9]{20,}|AKIA[0-9A-Z]{16}|AIza[0-9A-Za-z\-_]{30,})\b"
)
MRN_RE = re.compile(r"\bMRN[-:\s]?\d{6,10}\b", re.IGNORECASE)
CDL_RE = re.compile(r"\bCDL[-:\s]?[A-Z]{2}[-:\s]?\d{5,9}\b", re.IGNORECASE)
ROUTING_ACCOUNT_RE = re.compile(
    r"\b(?:ABA|ROUTING|ACCT|ACCOUNT)[-:\s#]*\d{8,17}\b", re.IGNORECASE
)


def luhn_valid(digits: str) -> bool:
    """Validate a candidate payment card number using the Luhn algorithm."""
    if not digits.isdigit() or not (13 <= len(digits) <= 19):
        return False
    total = 0
    reverse_digits = digits[::-1]
    for idx, ch in enumerate(reverse_digits):
        n = int(ch)
        if idx % 2 == 1:
            n *= 2
            if n > 9:
                n -= 9
        total += n
    return total % 10 == 0


def shannon_entropy(text: str) -> float:
    """Compute character-level Shannon entropy in bits."""
    if not text:
        return 0.0
    counts = Counter(text)
    length = len(text)
    return -sum((c / length) * math.log2(c / length) for c in counts.values())


def canonicalize(text: str) -> str:
    """Strip diacritics, NFKC-normalize, strip zero-width chars, fold homoglyphs, collapse whitespace."""
    nfkd = unicodedata.normalize("NFKD", text)
    no_marks = "".join(ch for ch in nfkd if unicodedata.category(ch) != "Mn")
    nfkc = unicodedata.normalize("NFKC", no_marks)
    cleaned = ZERO_WIDTH_RE.sub("", nfkc)
    folded = cleaned.translate(HOMOGLYPH_MAP).lower()
    return WHITESPACE_RE.sub(" ", folded).strip()


def _punct_stripped(normalized_text: str) -> str:
    """Secondary scan surface with punctuation removed to catch dot/hyphen-split phrases."""
    return WHITESPACE_RE.sub(" ", PUNCT_STRIP_RE.sub("", normalized_text)).strip()


def extract_decoded_segments(text: str, max_depth: int = 2) -> List[str]:
    """Bounded recursive decoding of URL-encoded, Base64, and Hex payloads."""
    decoded_surfaces: List[str] = []
    seen = {text}
    frontier = [text]

    def _add_surface(raw_val: str) -> None:
        canon = canonicalize(raw_val)
        if canon:
            decoded_surfaces.append(canon)
            punct = _punct_stripped(canon)
            if punct and punct != canon:
                decoded_surfaces.append(punct)

    for _ in range(max_depth):
        next_frontier: List[str] = []
        for item in frontier:
            if "%" in item:
                url_dec = unquote(item)
                if url_dec not in seen:
                    seen.add(url_dec)
                    _add_surface(url_dec)
                    next_frontier.append(url_dec)

            for match in BASE64_CANDIDATE_RE.findall(item):
                try:
                    raw = base64.b64decode(match, validate=True).decode(
                        "utf-8", errors="ignore"
                    )
                    if raw and len(raw) >= 8 and raw not in seen:
                        seen.add(raw)
                        _add_surface(raw)
                        next_frontier.append(raw)
                except Exception:
                    pass

            for match in HEX_CANDIDATE_RE.findall(item):
                hex_str = match[2:] if match.lower().startswith("0x") else match
                if len(hex_str) % 2 == 0:
                    try:
                        raw = bytes.fromhex(hex_str).decode("utf-8", errors="ignore")
                        if raw and len(raw) >= 8 and raw not in seen:
                            seen.add(raw)
                            _add_surface(raw)
                            next_frontier.append(raw)
                    except Exception:
                        pass
        frontier = next_frontier
        if not frontier:
            break

    return decoded_surfaces


@dataclass
class EvaluationResult:
    """Structured decision returned by the policy engine."""

    allowed: bool
    action: str  # "ALLOW", "ALLOW_REDACTED", "BLOCK"
    http_status: int
    vector: Optional[str] = None
    reason: Optional[str] = None
    sanitized_text: str = ""
    redactions: List[str] = field(default_factory=list)
    policy_pack: str = "general_enterprise"
    compliance_tags: List[str] = field(default_factory=list)


class PolicyPack:
    """Compiled policy pack loaded from a YAML specification."""

    def __init__(self, spec: Dict[str, Any]) -> None:
        self.name: str = spec["name"]
        self.version: str = str(spec.get("version", "1.0"))
        self.description: str = spec.get("description", "")
        self.compliance_frameworks: List[str] = spec.get("compliance_frameworks", [])
        self.blocked_phrases: List[str] = [
            p.lower() for p in spec.get("blocked_phrases", [])
        ]
        self.social_engineering_phrases: List[str] = [
            p.lower() for p in spec.get("social_engineering_phrases", [])
        ]
        self.benign_allow_phrases: List[str] = [
            p.lower() for p in spec.get("benign_allow_phrases", [])
        ]
        self.output_block_phrases: List[str] = [
            p.lower() for p in spec.get("output_block_phrases", [])
        ]
        self.pii_redaction: List[str] = spec.get("pii_redaction", [])
        self.block_on_pii_output: List[str] = spec.get("block_on_pii_output", [])
        self.flood_limits: Dict[str, Any] = spec.get("flood_limits", {})
        self.numeric_limits: List[Dict[str, Any]] = spec.get("numeric_limits", [])
        self.domain_block_patterns: List[Tuple[str, re.Pattern[str]]] = [
            (item["name"], re.compile(item["pattern"], re.IGNORECASE))
            for item in spec.get("domain_block_patterns", [])
        ]


class PolicyEngine:
    """Loads YAML policy packs and evaluates both inputs and model outputs."""

    def __init__(self, policy_dir: Path) -> None:
        self.policy_dir = policy_dir
        self.packs: Dict[str, PolicyPack] = {}
        self.reload()

    def reload(self) -> None:
        self.packs.clear()
        if not self.policy_dir.exists():
            return
        for path in sorted(self.policy_dir.glob("*.yaml")):
            with path.open("r", encoding="utf-8") as fh:
                spec = yaml.safe_load(fh)
            pack = PolicyPack(spec)
            self.packs[pack.name] = pack

    def get_pack(self, name: str) -> PolicyPack:
        if name not in self.packs:
            raise KeyError(f"Unknown policy pack: {name}")
        return self.packs[name]

    def list_packs(self) -> List[Dict[str, Any]]:
        return [
            {
                "name": p.name,
                "version": p.version,
                "description": p.description,
                "compliance_frameworks": p.compliance_frameworks,
            }
            for p in self.packs.values()
        ]

    def _check_flood(self, text: str, pack: PolicyPack) -> Optional[str]:
        limits = pack.flood_limits
        if not limits:
            return None
        max_repeat_char = int(limits.get("max_repeat_char", 25))
        if re.search(rf"(.)\1{{{max_repeat_char},}}", text):
            return "repeating_character_flood"

        words = re.findall(r"\b\w+\b", text.lower())
        max_repeat_word = int(limits.get("max_repeat_word", 15))
        if len(words) >= max_repeat_word:
            most_common_word, count = Counter(words).most_common(1)[0]
            if count >= max_repeat_word and (count / len(words)) > 0.6:
                return f"repeating_word_flood:{most_common_word}"

        min_entropy_len = int(limits.get("min_entropy_length", 80))
        max_entropy = float(limits.get("max_shannon_entropy", 5.2))
        if len(text) >= min_entropy_len and " " not in text.strip():
            if shannon_entropy(text.strip()) >= max_entropy:
                return "high_entropy_gibberish_flood"
        return None

    def _redact_pii(self, text: str, types: List[str]) -> Tuple[str, List[str]]:
        sanitized = text
        found: List[str] = []

        if "BANK_ACCOUNT" in types and ROUTING_ACCOUNT_RE.search(sanitized):
            sanitized = ROUTING_ACCOUNT_RE.sub("[REDACTED_ACCOUNT]", sanitized)
            found.append("BANK_ACCOUNT")

        if "MRN" in types and MRN_RE.search(sanitized):
            sanitized = MRN_RE.sub("[REDACTED_MRN]", sanitized)
            found.append("MRN")

        if "CDL" in types and CDL_RE.search(sanitized):
            sanitized = CDL_RE.sub("[REDACTED_CDL]", sanitized)
            found.append("CDL")

        if "API_SECRET" in types and API_SECRET_RE.search(sanitized):
            sanitized = API_SECRET_RE.sub("[REDACTED_SECRET]", sanitized)
            found.append("API_SECRET")

        if "SSN" in types and SSN_RE.search(sanitized):
            sanitized = SSN_RE.sub("[REDACTED_SSN]", sanitized)
            found.append("SSN")

        if "PAN" in types:
            def _replace_pan(match: re.Match[str]) -> str:
                raw = match.group(0)
                digits = re.sub(r"[ -]", "", raw)
                if luhn_valid(digits):
                    if "PAN" not in found:
                        found.append("PAN")
                    return "[REDACTED_PAN]"
                return raw

            sanitized = PAN_CANDIDATE_RE.sub(_replace_pan, sanitized)

        if "EMAIL" in types and EMAIL_RE.search(sanitized):
            sanitized = EMAIL_RE.sub("[REDACTED_EMAIL]", sanitized)
            found.append("EMAIL")

        if "PHONE" in types and PHONE_RE.search(sanitized):
            sanitized = PHONE_RE.sub("[REDACTED_PHONE]", sanitized)
            found.append("PHONE")

        return sanitized, sorted(set(found))

    def evaluate_input(
        self,
        text: str,
        policy_name: str,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> EvaluationResult:
        pack = self.get_pack(policy_name)
        normalized = canonicalize(text)
        punct_clean = _punct_stripped(normalized)
        decoded_segments = extract_decoded_segments(text, max_depth=2)
        surfaces = [normalized, punct_clean] + decoded_segments

        flood_hit = self._check_flood(text, pack)
        if flood_hit:
            return EvaluationResult(
                allowed=False,
                action="BLOCK",
                http_status=400,
                vector="resilience.flood_blocked",
                reason=f"Blocked anomalous input ({flood_hit})",
                policy_pack=pack.name,
                compliance_tags=pack.compliance_frameworks,
            )

        is_benign_educational = (
            any(allow in normalized for allow in pack.benign_allow_phrases)
            and not EXFIL_ACTION_RE.search(normalized)
            and not EXFIL_ACTION_RE.search(punct_clean)
        )
        for idx, surface in enumerate(surfaces):
            if SYSTEM_PROMPT_EXFIL_RE.search(surface):
                source_tag = "encoded_payload" if idx > 1 else "direct_or_obfuscated"
                return EvaluationResult(
                    allowed=False,
                    action="BLOCK",
                    http_status=400,
                    vector="security.prompt_injection",
                    reason=f"Blocked prompt injection ({source_tag})",
                    policy_pack=pack.name,
                    compliance_tags=pack.compliance_frameworks,
                )
            for phrase in pack.blocked_phrases:
                if phrase in surface:
                    if idx <= 1 and is_benign_educational and phrase == "system prompt":
                        continue
                    source_tag = "encoded_payload" if idx > 1 else "direct_or_obfuscated"
                    return EvaluationResult(
                        allowed=False,
                        action="BLOCK",
                        http_status=400,
                        vector="security.prompt_injection",
                        reason=f"Blocked prompt injection ({source_tag})",
                        policy_pack=pack.name,
                        compliance_tags=pack.compliance_frameworks,
                    )

        for surface in surfaces:
            for phrase in pack.social_engineering_phrases:
                if phrase in surface:
                    return EvaluationResult(
                        allowed=False,
                        action="BLOCK",
                        http_status=400,
                        vector="security.social_engineering",
                        reason="Blocked social-engineering authority pretext",
                        policy_pack=pack.name,
                        compliance_tags=pack.compliance_frameworks,
                    )

        for rule_name, pattern in pack.domain_block_patterns:
            if any(pattern.search(surface) for surface in surfaces):
                return EvaluationResult(
                    allowed=False,
                    action="BLOCK",
                    http_status=422,
                    vector=f"domain.{rule_name}",
                    reason=f"Blocked domain compliance violation ({rule_name})",
                    policy_pack=pack.name,
                    compliance_tags=pack.compliance_frameworks,
                )

        metadata = metadata or {}
        for rule in pack.numeric_limits:
            field_name = rule["field"]
            if field_name not in metadata or metadata[field_name] is None:
                return EvaluationResult(
                    allowed=False,
                    action="BLOCK",
                    http_status=422,
                    vector="domain.missing_numeric_metadata",
                    reason=f"Required numeric field '{field_name}' is missing",
                    policy_pack=pack.name,
                    compliance_tags=pack.compliance_frameworks,
                )

            raw_val = metadata[field_name]
            if isinstance(raw_val, bool):
                return EvaluationResult(
                    allowed=False,
                    action="BLOCK",
                    http_status=422,
                    vector="domain.invalid_numeric_metadata",
                    reason=f"Field '{field_name}' must be a finite number, not boolean",
                    policy_pack=pack.name,
                    compliance_tags=pack.compliance_frameworks,
                )
            try:
                val = float(raw_val)
            except (TypeError, ValueError):
                return EvaluationResult(
                    allowed=False,
                    action="BLOCK",
                    http_status=422,
                    vector="domain.invalid_numeric_metadata",
                    reason=f"Field '{field_name}' must be a valid finite number",
                    policy_pack=pack.name,
                    compliance_tags=pack.compliance_frameworks,
                )
            if not math.isfinite(val):
                return EvaluationResult(
                    allowed=False,
                    action="BLOCK",
                    http_status=422,
                    vector="domain.invalid_numeric_metadata",
                    reason=f"Field '{field_name}' must be finite (NaN/Inf rejected)",
                    policy_pack=pack.name,
                    compliance_tags=pack.compliance_frameworks,
                )
            if "max" in rule and val > float(rule["max"]):
                return EvaluationResult(
                    allowed=False,
                    action="BLOCK",
                    http_status=422,
                    vector=f"domain.{rule['name']}",
                    reason=f"Field '{field_name}' ({val}) exceeds limit ({rule['max']})",
                    policy_pack=pack.name,
                    compliance_tags=pack.compliance_frameworks,
                )
            if "min" in rule and val < float(rule["min"]):
                return EvaluationResult(
                    allowed=False,
                    action="BLOCK",
                    http_status=422,
                    vector=f"domain.{rule['name']}",
                    reason=f"Field '{field_name}' ({val}) below minimum ({rule['min']})",
                    policy_pack=pack.name,
                    compliance_tags=pack.compliance_frameworks,
                )

        sanitized, redactions = self._redact_pii(text, pack.pii_redaction)
        action = "ALLOW_REDACTED" if redactions else "ALLOW"
        return EvaluationResult(
            allowed=True,
            action=action,
            http_status=200,
            sanitized_text=sanitized,
            redactions=redactions,
            policy_pack=pack.name,
            compliance_tags=pack.compliance_frameworks,
        )

    def evaluate_output(self, text: str, policy_name: str) -> EvaluationResult:
        """Inspect upstream LLM output on both raw and canonicalized surfaces."""
        pack = self.get_pack(policy_name)
        normalized = canonicalize(text)
        surfaces = (text, normalized)

        for phrase in pack.output_block_phrases:
            if phrase in normalized:
                return EvaluationResult(
                    allowed=False,
                    action="BLOCK",
                    http_status=500,
                    vector="security.output_instruction_leak",
                    reason="Upstream model output leaked protected system instructions",
                    policy_pack=pack.name,
                    compliance_tags=pack.compliance_frameworks,
                )

        if "SSN" in pack.block_on_pii_output and any(SSN_RE.search(s) for s in surfaces):
            return EvaluationResult(
                allowed=False,
                action="BLOCK",
                http_status=500,
                vector="security.output_pii_exfiltration",
                reason="Upstream model output attempted raw SSN exfiltration",
                policy_pack=pack.name,
                compliance_tags=pack.compliance_frameworks,
            )

        if "API_SECRET" in pack.block_on_pii_output and any(
            API_SECRET_RE.search(s) for s in surfaces
        ):
            return EvaluationResult(
                allowed=False,
                action="BLOCK",
                http_status=500,
                vector="security.output_secret_exfiltration",
                reason="Upstream model output attempted raw API secret exfiltration",
                policy_pack=pack.name,
                compliance_tags=pack.compliance_frameworks,
            )

        if "MRN" in pack.block_on_pii_output and any(MRN_RE.search(s) for s in surfaces):
            return EvaluationResult(
                allowed=False,
                action="BLOCK",
                http_status=500,
                vector="security.output_phi_exfiltration",
                reason="Upstream model output attempted raw MRN/PHI exfiltration",
                policy_pack=pack.name,
                compliance_tags=pack.compliance_frameworks,
            )

        for rule_name, pattern in pack.domain_block_patterns:
            if any(pattern.search(s) for s in surfaces):
                return EvaluationResult(
                    allowed=False,
                    action="BLOCK",
                    http_status=500,
                    vector=f"domain.output_{rule_name}",
                    reason=f"Upstream model output violated domain policy ({rule_name})",
                    policy_pack=pack.name,
                    compliance_tags=pack.compliance_frameworks,
                )

        sanitized, redactions = self._redact_pii(text, pack.pii_redaction)
        return EvaluationResult(
            allowed=True,
            action="ALLOW_REDACTED" if redactions else "ALLOW",
            http_status=200,
            sanitized_text=sanitized,
            redactions=redactions,
            policy_pack=pack.name,
            compliance_tags=pack.compliance_frameworks,
        )