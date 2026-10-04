"""A small built-in list of very common passwords.

Kept intentionally short (~100 entries). The goal is to catch the most
obvious cases (password123, qwerty, admin, letmein, etc.) without shipping
a multi-megabyte dictionary.
"""

from __future__ import annotations

# Sorted for readability, not for any algorithmic purpose.
COMMON_PASSWORDS = frozenset({
    "123456", "12345678", "123456789", "1234567890", "12345",
    "111111", "000000", "222222", "123123", "121212",
    "qwerty", "qwerty123", "qwertyuiop", "asdfgh", "asdfghjkl",
    "zxcvbn", "zxcvbnm", "1q2w3e4r", "qazwsx", "qazwsxedc",
    "password", "password1", "password123", "passw0rd", "p@ssw0rd",
    "admin", "admin123", "administrator", "root", "toor",
    "letmein", "welcome", "welcome1", "monkey", "dragon",
    "iloveyou", "sunshine", "princess", "football", "baseball",
    "abc123", "abcdef", "abcd1234", "a1b2c3", "123abc",
    "master", "shadow", "superman", "batman", "trustno1",
    "access", "flower", "hello", "hello123", "whatever",
    "freedom", "starwars", "michael", "jennifer", "jordan",
    "hunter", "hunter2", "charlie", "thomas", "robert",
    "login", "loveme", "654321", "666666", "777777",
    "1111111", "1234", "123", "test", "test123",
    "guest", "default", "changeme", "secret", "pass",
    "kali", "kali123", "debian", "ubuntu", "linux",
    "matrix", "neo", "morpheus", "trinity", "hacker",
    "samsung", "google", "facebook", "twitter", "youtube",
    "iloveu", "nothing", "whatever1", "computer", "internet",
})


def is_common(password: str) -> bool:
    """Return True if the password is in the built-in common list.

    Comparison is case-insensitive so 'PASSWORD123' is still caught.
    """
    return password.lower() in COMMON_PASSWORDS
