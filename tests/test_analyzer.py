"""Tests for the analyzer."""

import pytest

from password_strength.analyzer import (
    SCORE_LABELS,
    analyze,
)


def test_analyze_returns_analysis():
    a = analyze("correct-horse-battery-staple")
    assert a.password_length == 28
    assert 0 <= a.score <= 4
    assert a.label in SCORE_LABELS


def test_empty_password_is_very_weak():
    a = analyze("")
    assert a.score == 0
    assert a.password_length == 0


def test_common_password_is_penalized():
    a = analyze("password123")
    assert any("common" in p.lower() for p in a.penalties)
    assert a.score <= 1


def test_short_password_penalized():
    a = analyze("aB1!")
    assert any("shorter than" in p for p in a.penalties)


def test_repeats_detected():
    a = analyze("aaaaBBBB1234")
    assert any("repeated" in p for p in a.penalties)


def test_sequences_detected():
    a = analyze("abcXYZ987")
    assert any("sequential" in p for p in a.penalties)


def test_keyboard_walk_detected():
    a = analyze("qwertyXYZ!")
    assert any("keyboard" in p for p in a.penalties)


def test_digits_only_penalized():
    a = analyze("1234567890")
    assert any("only digits" in p for p in a.penalties)


def test_letters_only_penalized():
    a = analyze("abcdefghijklmnopqrstuvwxyz")
    assert any("only letters" in p for p in a.penalties)


def test_strong_random_password_scores_high():
    a = analyze("Xk9!mQ2#vL7$nR4@pW")
    assert a.score >= 3
    assert a.penalties == [] or all("common" not in p for p in a.penalties)


def test_passphrase_scores_reasonably():
    a = analyze("correct-horse-battery-staple")
    assert a.score >= 3


def test_non_string_raises():
    with pytest.raises(TypeError):
        analyze(12345)


def test_suggestions_present_for_weak():
    a = analyze("abc")
    assert a.suggestions
