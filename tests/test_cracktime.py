"""Tests for the crack-time estimator."""

from password_strength.cracktime import (
    ATTACK_SPEEDS,
    crack_times,
    seconds_to_human,
)


def test_crack_times_has_all_scenarios():
    times = crack_times(40.0)
    assert set(times.keys()) == set(ATTACK_SPEEDS.keys())


def test_crack_times_higher_entropy_is_longer():
    short = crack_times(20.0)["offline_slow_hash"]
    long = crack_times(80.0)["offline_slow_hash"]
    assert short != long


def test_crack_times_zero_entropy_is_instant():
    times = crack_times(0.0)
    assert all(v == "instant" for v in times.values())


def test_seconds_to_human_units():
    assert seconds_to_human(0.0001) == "instant"
    assert "ms" in seconds_to_human(0.01)
    assert "seconds" in seconds_to_human(5)
    assert "minutes" in seconds_to_human(120)
    assert "hours" in seconds_to_human(7200)
    assert "days" in seconds_to_human(86400 * 5)
    assert "months" in seconds_to_human(86400 * 100)
    assert "years" in seconds_to_human(86400 * 365 * 10)


def test_seconds_to_human_extreme():
    # Enormous entropy => centuries+
    assert seconds_to_human(1e30) == "centuries+"
