"""Core password strength analysis: entropy + pattern detection + scoring."""

from __future__ import annotations

import math
import re
from dataclasses import dataclass, field
from typing import List

from .common import is_common


# Character-class pools used for entropy estimation.
LOWER = "abcdefghijklmnopqrstuvwxyz"
UPPER = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
DIGITS = "0123456789"
SYMBOLS = "!@#$%^&*()-_=+[]{}|;:',.<>/?`~\"\\"

KEYBOARD_ROWS = [
    "qwertyuiop",
    "asdfghjkl",
    "zxcvbnm",
    "1234567890",
]

SEQUENCES = [
    "abcdefghijklmnopqrstuvwxyz",
    "01234567890",
    "qwertyuiop",
    "asdfghjkl",
    "zxcvbnm",
]

SCORE_LABELS = ["Very Weak", "Weak", "Fair", "Strong", "Very Strong"]


@dataclass
class Analysis:
    """Result of analyzing a password."""

    password_length: int
    character_pool_size: int
    raw_entropy_bits: float
    adjusted_entropy_bits: float
    score: int                       # 0 - 4
    label: str
    penalties: List[str] = field(default_factory=list)
    suggestions: List[str] = field(default_factory=list)


def _character_pool_size(password: str) -> int:
    size = 0
    if any(c in LOWER for c in password):
        size += len(LOWER)
    if any(c in UPPER for c in password):
        size += len(UPPER)
    if any(c in DIGITS for c in password):
        size += len(DIGITS)
    if any(c in SYMBOLS for c in password):
        size += len(SYMBOLS)
    return size or 1


def _has_repeats(password: str, min_run: int = 3) -> bool:
    """True if the password has a run of the same character, e.g. 'aaa'."""
    return re.search(r"(.)\1{" + str(min_run - 1) + r",}", password) is not None


def _has_sequence(password: str, min_len: int = 3) -> bool:
    """True if the password contains a run of 3+ sequential characters."""
    lower = password.lower()
    for seq in SEQUENCES:
        for i in range(len(seq) - min_len + 1):
            chunk = seq[i:i + min_len]
            if chunk in lower:
                return True
            if chunk[::-1] in lower:
                return True
    return False


def _has_keyboard_walk(password: str, min_len: int = 4) -> bool:
    """True if the password contains a horizontal keyboard walk, e.g. 'qwer'."""
    lower = password.lower()
    for row in KEYBOARD_ROWS:
        for i in range(len(row) - min_len + 1):
            chunk = row[i:i + min_len]
            if chunk in lower or chunk[::-1] in lower:
                return True
    return False


def analyze(password: str) -> Analysis:
    """Analyze a password and return an Analysis object.

    The password is never logged or persisted; this function is pure.
    """
    if not isinstance(password, str):
        raise TypeError("password must be a string")

    length = len(password)
    pool = _character_pool_size(password)

    # Raw entropy: L * log2(pool). Classic NIST-style estimate.
    raw_entropy = length * math.log2(pool) if length else 0.0

    penalties: List[str] = []
    adjusted = raw_entropy

    # --- Pattern penalties ---
    if length < 8:
        penalties.append("shorter than 8 characters")
        adjusted *= 0.5
    elif length < 12:
        penalties.append("shorter than 12 characters")
        adjusted *= 0.85

    if _has_repeats(password):
        penalties.append("contains repeated characters (e.g. 'aaa')")
        adjusted *= 0.7

    if _has_sequence(password):
        penalties.append("contains a sequential run (e.g. 'abc' or '123')")
        adjusted *= 0.8

    if _has_keyboard_walk(password):
        penalties.append("contains a keyboard walk (e.g. 'qwer')")
        adjusted *= 0.7

    if is_common(password):
        penalties.append("appears in the built-in list of common passwords")
        adjusted = min(adjusted, 4.0)

    if password.isdigit():
        penalties.append("only digits")
        adjusted *= 0.6
    elif password.isalpha():
        penalties.append("only letters")
        adjusted *= 0.85

    adjusted = max(adjusted, 0.0)

    # --- Score mapping (bits -> 0..4) ---
    if adjusted < 28:
        score = 0
    elif adjusted < 40:
        score = 1
    elif adjusted < 60:
        score = 2
    elif adjusted < 80:
        score = 3
    else:
        score = 4

    suggestions = _suggestions(length, pool, penalties, score)

    return Analysis(
        password_length=length,
        character_pool_size=pool,
        raw_entropy_bits=round(raw_entropy, 2),
        adjusted_entropy_bits=round(adjusted, 2),
        score=score,
        label=SCORE_LABELS[score],
        penalties=penalties,
        suggestions=suggestions,
    )


def _suggestions(length: int, pool: int, penalties: List[str], score: int) -> List[str]:
    # Score 4 = already excellent. Only show a positive note.
    if score >= 4:
        return ["Excellent. Stored safely in a password manager, this is very strong."]

    tips: List[str] = []

    if any("common" in p for p in penalties):
        tips.append("Avoid well-known passwords.")
    if any("sequential" in p or "keyboard" in p or "repeated" in p for p in penalties):
        tips.append("Avoid patterns like 'abc', '123', 'qwerty', or 'aaa'.")
    if length < 12:
        tips.append("Use at least 12-16 characters.")
    if pool < len(LOWER) + len(UPPER) + len(DIGITS):
        tips.append("Mix uppercase, lowercase, and digits.")
    if pool < len(LOWER) + len(UPPER) + len(DIGITS) + len(SYMBOLS):
        tips.append("Add a few symbols (e.g. ! @ # $ %).")

    if score == 3:
        tips.append("Close to great. A longer passphrase or one more character class will push it over.")
    elif score < 3 and not tips:
        tips.append("Try a random passphrase of 4+ unrelated words, or a longer random string.")

    return tips
