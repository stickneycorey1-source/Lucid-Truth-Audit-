"""YAML Policy-Pack Engine for Lucid-Truth-Audit Enterprise.

Handles:
1. Unicode/homoglyph/zero-width canonicalization + Base64/Hex decoding
2. Prompt injection & social-engineering pretext blocking
3. Flooding / high-entropy gibberish defense
4. PII / PHI / PCI detection and deterministic redaction (including Luhn PAN check)
5. Industry-specific domain guardrails (FMCSA logistics, HIPAA, PCI-DSS, custom rules)
6. Output-boundary leak prevention (system prompts, secrets, raw SSNs)
"""

from __future__ import annotations

import base64
import math
import re
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import yaml

ZERO_WIDTH_RE = re.compile(r"[\u200b\u200c\u200d\u2060\ufeff]")
HOMOGLYPH_MAP = str.maketrans(
    {
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
    
