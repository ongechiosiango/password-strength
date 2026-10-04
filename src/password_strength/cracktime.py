"""Convert entropy in bits to estimated crack time at various attack speeds.

Estimates assume an attacker must try 2^(entropy-1) guesses on average to
find the password (half the search space). Real-world time depends on the
hash function, hardware, and whether the attacker has a good wordlist.
"""

from __future__ import annotations


# Guesses per second for typical attack scenarios.
ATTACK_SPEEDS = {
    "online_throttled":   100 / 3600,       # 100 guesses/hour
    "online_unthrottled": 10,               # 10 guesses/sec
    "offline_slow_hash":  10_000,           # bcrypt / argon2, moderate hardware
    "offline_fast_hash":  10_000_000_000,   # SHA-256 / MD5 on a GPU rig
}

ATTACK_LABELS = {
    "online_throttled":   "Online (throttled)",
    "online_unthrottled": "Online (unthrottled)",
    "offline_slow_hash":  "Offline (slow hash)",
    "offline_fast_hash":  "Offline (fast hash)",
}


def seconds_to_human(seconds: float) -> str:
    """Return a human-friendly string like '3.5 years' or 'centuries'."""
    if seconds < 1e-3:
        return "instant"
    if seconds < 1:
        return f"{seconds * 1000:.0f} ms"
    if seconds < 60:
        return f"{seconds:.1f} seconds"
    minutes = seconds / 60
    if minutes < 60:
        return f"{minutes:.1f} minutes"
    hours = minutes / 60
    if hours < 24:
        return f"{hours:.1f} hours"
    days = hours / 24
    if days < 30:
        return f"{days:.1f} days"
    months = days / 30
    if months < 12:
        return f"{months:.1f} months"
    years = days / 365.25
    if years < 1_000:
        return f"{years:.1f} years"
    if years < 1_000_000:
        return f"{years / 1_000:.1f} thousand years"
    if years < 1_000_000_000:
        return f"{years / 1_000_000:.1f} million years"
    return "centuries+"


def crack_times(entropy_bits: float) -> dict:
    """Return a dict of {attack_scenario: human_readable_time}."""
    if entropy_bits <= 0:
        return {k: "instant" for k in ATTACK_SPEEDS}

    # Average guesses needed = 2^(entropy - 1)
    guesses = 2 ** (entropy_bits - 1)
    return {
        scenario: seconds_to_human(guesses / speed)
        for scenario, speed in ATTACK_SPEEDS.items()
    }
