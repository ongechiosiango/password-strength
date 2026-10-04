"""Tests for the common-password list."""

from password_strength.common import COMMON_PASSWORDS, is_common


def test_common_list_not_empty():
    assert len(COMMON_PASSWORDS) >= 50


def test_is_common_hits_known_entry():
    assert is_common("password")
    assert is_common("123456")
    assert is_common("qwerty")


def test_is_common_is_case_insensitive():
    assert is_common("PASSWORD")
    assert is_common("Qwerty")


def test_is_common_misses_random():
    assert not is_common("zqf8R!k2pWn9")
    assert not is_common("Xk9!mQ2#vL")
