
import pytest

from app.safe_connection import check_ip


def test_public_ip():
    assert check_ip("8.8.8.8") is True


def test_private_ip():
    assert check_ip("192.168.1.10") is False


def test_localhost():
    assert check_ip("127.0.0.1") is False


def test_internal_network():
    assert check_ip("10.0.0.5") is False


def test_link_local():
    assert check_ip("169.254.1.1") is False


def test_invalid_ip():
    assert check_ip("not-an-ip") is False
