import logging
import math
import re
import time
from collections import defaultdict, deque
from typing import Deque, Dict, List, Literal
from fastapi import HTTPException
from pydantic import BaseModel, ConfigDict, Field

logger = logging.getLogger("lucid_truth_audit")

# --- 1. SLIDING-WINDOW RATE LIMITER (HTTP 429) ---
class SlidingWindowRateLimiter:
    def __init__(self, max_requests: int = 30, window_seconds: float = 60.0) -> None:
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self._buckets: Dict[str, Deque[float]] = defaultdict(deque)

    def check(self, client_key: str) -> None:
        now = time.monotonic()
        bucket = self._buckets[client_key]
        cutoff = now - self.window_seconds
        while bucket and bucket[0] <= cutoff:
            bucket.popleft()
        if len(bucket) >= self.max_requests:
            logger.warning("security.rate_limit_exceeded")
            raise HTTPException(
                status_code=429,
                detail="Too Many Requests: Rate limit exceeded for API key.",
            )
        bucket.append(now)

    def reset(self) -> None:
        self._buckets.clear()


rate_limiter = SlidingWindowRateLimiter(max_requests=30, window_seconds=60.0)


# --- 2. REPETITION & SHANNON ENTROPY ANOMALY DETECTOR (HTTP 400) ---
REPEATING_CHAR_PATTERN = re.compile(r"(.)\1{24,}")
REPEATING_TOKEN_PATTERN = re.compile(r"(\b\w+\b)(?:\s+\1){14,}", re.IGNORECASE)


def _shannon_entropy(text: str) -> float:
    if not text:
        return 0.0
    counts: Dict[str, int] = defaultdict(int)
    for ch in text:
        counts[ch] += 1
    length = len(text)
    return -sum((c / length) * math.log2(c / length) for c in counts.values())


def scan_payload_anomalies(text: str) -> None:
    """Blocks token-buffer repetition floods and extreme high-entropy gibberish payloads."""
    if REPEATING_CHAR_PATTERN.search(text) or REPEATING_TOKEN_PATTERN.search(text):
        logger.warning("security.input_blocked category=anomaly_repeating_chars")
        raise HTTPException(
            status_code=400,
            detail="Bad Request: Degenerate character or token repetition anomaly detected.",
        )

    compact = re.sub(r"\s+", "", text)
    if len(compact) >= 120 and _shannon_entropy(compact) > 5.4:
        logger.warning("security.input_blocked category=anomaly_high_entropy")
        raise HTTPException(
            status_code=400,
            detail="Bad Request: Anomalous high-entropy payload detected.",
        )


# --- 3. MULTI-TURN CONVERSATION HISTORY ISOLATION (PYDANTIC V2) ---
class ConversationTurn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    role: Literal["user", "assistant"]
    content: str = Field(..., min_length=1, max_length=4000)


ROLE_SPOOF_PATTERN = re.compile(
    r"(?:^|\n)\s*(?:system|developer|root|admin)\s*:",
    re.IGNORECASE,
)


def validate_conversation_history(history: List[ConversationTurn]) -> None:
    """Prevents role-spoofing headers and embedded instruction overrides inside prior turns."""
    for turn in history:
        if ROLE_SPOOF_PATTERN.search(turn.content):
            logger.warning("security.input_blocked category=multi_turn_role_spoof")
            raise HTTPException(
                status_code=400,
                detail="Bad Request: Spoofed system/developer role marker in conversation history.",
            )
