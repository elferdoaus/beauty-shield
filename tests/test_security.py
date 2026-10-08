
from unittest.mock import patch
from app.security import validate_url


def fake_dns(hostname, port, type):
    if hostname == "private.example":
        ip = "192.168.1.10"
    else:
        ip = "93.184.215.14"

    return [(2, 1, 6, "", (ip, port))]


def test_public_url():
    with patch("app.security.socket.getaddrinfo", side_effect=fake_dns):
        assert validate_url("https://example.com") is True


def test_localhost():
    assert validate_url("http://localhost") is False


def test_private_ip():
    assert validate_url("http://127.0.0.1") is False


def test_private_dns():
    with patch("app.security.socket.getaddrinfo", side_effect=fake_dns):
        assert validate_url("https://private.example") is False


def test_invalid_protocol():
    assert validate_url("file:///etc/passwd") is False


def test_restricted_port():
    assert validate_url("http://example.com:8080") is False

def test_domain_not_allowed():
    assert validate_url("https://google.com") is False
