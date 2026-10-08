
import pytest
from unittest.mock import patch

from app.safe_connection import check_ip, resolve_public_ips


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


def test_resolve_public_ip():
    fake_addresses = [
        (2, 1, 6, "", ("8.8.8.8", 443))
    ]

    with patch(
        "app.safe_connection.socket.getaddrinfo",
        return_value=fake_addresses
    ):
        result = resolve_public_ips("example.com", 443)

    assert result == ["8.8.8.8"]


def test_resolve_private_ip():
    fake_addresses = [
        (2, 1, 6, "", ("192.168.1.10", 443))
    ]

    with patch(
        "app.safe_connection.socket.getaddrinfo",
        return_value=fake_addresses
    ):
        with pytest.raises(ValueError):
            resolve_public_ips("example.com", 443)


def test_resolve_mixed_ips():
    fake_addresses = [
        (2, 1, 6, "", ("8.8.8.8", 443)),
        (2, 1, 6, "", ("127.0.0.1", 443))
    ]

    with patch(
        "app.safe_connection.socket.getaddrinfo",
        return_value=fake_addresses
    ):
        with pytest.raises(ValueError):
            resolve_public_ips("example.com", 443)
