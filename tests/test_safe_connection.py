
import socket
import urllib3
import pytest

from unittest.mock import MagicMock, patch

from app.safe_connection import check_ip, resolve_public_ips, safe_get


def test_public_ip():
    assert check_ip("8.8.8.8") is True


def test_private_ip():
    assert check_ip("192.168.1.1") is False


def test_localhost():
    assert check_ip("127.0.0.1") is False


def test_internal_network():
    assert check_ip("10.0.0.1") is False


def test_link_local():
    assert check_ip("169.254.1.1") is False


def test_invalid_ip():
    assert check_ip("not-an-ip") is False


def test_resolve_public_ip():
    fake_addresses = [
        (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("8.8.8.8", 443))
    ]

    with patch(
        "app.safe_connection.socket.getaddrinfo",
        return_value=fake_addresses
    ):
        result = resolve_public_ips("example.com", 443)

    assert result == ["8.8.8.8"]


def test_resolve_private_ip():
    fake_addresses = [
        (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("192.168.1.1", 443))
    ]

    with patch(
        "app.safe_connection.socket.getaddrinfo",
        return_value=fake_addresses
    ):
        with pytest.raises(ValueError):
            resolve_public_ips("example.com", 443)


def test_resolve_mixed_ips():
    fake_addresses = [
        (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("8.8.8.8", 443)),
        (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 443))
    ]

    with patch(
        "app.safe_connection.socket.getaddrinfo",
        return_value=fake_addresses
    ):
        with pytest.raises(ValueError):
            resolve_public_ips("example.com", 443)


def test_safe_get_rejects_http():
    with pytest.raises(ValueError):
        safe_get("http://example.com")


def test_safe_get_rejects_invalid_url():
    with pytest.raises(ValueError):
        safe_get("https://")


def test_safe_get_rejects_private_dns():
    fake_addresses = [
        (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 443))
    ]

    with patch(
        "app.safe_connection.socket.getaddrinfo",
        return_value=fake_addresses
    ):
        with pytest.raises(ValueError):
            safe_get("https://example.com")


def test_safe_get_uses_validated_ip():
    fake_response = MagicMock()
    fake_response.status = 200

    fake_connection = MagicMock()
    fake_connection.request.return_value = fake_response

    with patch("app.safe_connection.validate_url", return_value=True):
        with patch(
            "app.safe_connection.resolve_public_ips",
            return_value=["8.8.8.8"]
        ):
            with patch(
                "app.safe_connection.urllib3.HTTPSConnectionPool",
                return_value=fake_connection
            ) as pool:
                response = safe_get("https://example.com/test")

    pool.assert_called_once()

    options = pool.call_args.kwargs

    assert options["host"] == "8.8.8.8"
    assert options["assert_hostname"] == "example.com"
    assert options["server_hostname"] == "example.com"
    assert response.status == 200

    fake_connection.close.assert_called_once()


def test_safe_get_preserves_query():
    fake_connection = MagicMock()
    fake_connection.request.return_value = MagicMock(status=200)

    with patch("app.safe_connection.validate_url", return_value=True):
        with patch(
            "app.safe_connection.resolve_public_ips",
            return_value=["8.8.8.8"]
        ):
            with patch(
                "app.safe_connection.urllib3.HTTPSConnectionPool",
                return_value=fake_connection
            ):
                safe_get("https://example.com/search?q=beauty")

    args = fake_connection.request.call_args.args

    assert args[1] == "/search?q=beauty"


def test_safe_get_rejects_unauthorized_domain():
    with patch("app.safe_connection.resolve_public_ips") as resolver:
        with pytest.raises(ValueError):
            safe_get("https://unauthorized-domain.test")

    resolver.assert_not_called()


def test_safe_get_closes_connection_on_error():
    fake_connection = MagicMock()

    fake_connection.request.side_effect = (
        urllib3.exceptions.HTTPError("Connection failed")
    )

    with patch("app.safe_connection.validate_url", return_value=True):
        with patch(
            "app.safe_connection.resolve_public_ips",
            return_value=["8.8.8.8"]
        ):
            with patch(
                "app.safe_connection.urllib3.HTTPSConnectionPool",
                return_value=fake_connection
            ):
                with pytest.raises(urllib3.exceptions.HTTPError):
                    safe_get("https://example.com")

    fake_connection.close.assert_called_once()


def test_safe_get_disables_preloading():
    fake_response = MagicMock()
    fake_response.status = 200

    fake_connection = MagicMock()
    fake_connection.request.return_value = fake_response

    with patch("app.safe_connection.validate_url", return_value=True):
        with patch(
            "app.safe_connection.resolve_public_ips",
            return_value=["8.8.8.8"]
        ):
            with patch(
                "app.safe_connection.urllib3.HTTPSConnectionPool",
                return_value=fake_connection
            ):
                safe_get("https://example.com")

    options = fake_connection.request.call_args.kwargs

    assert options["preload_content"] is False


def test_safe_get_closes_response():
    fake_response = MagicMock()
    fake_response.status = 200

    fake_connection = MagicMock()
    fake_connection.request.return_value = fake_response

    with patch("app.safe_connection.validate_url", return_value=True):
        with patch(
            "app.safe_connection.resolve_public_ips",
            return_value=["8.8.8.8"]
        ):
            with patch(
                "app.safe_connection.urllib3.HTTPSConnectionPool",
                return_value=fake_connection
            ):
                safe_get("https://example.com")

    fake_response.close.assert_called_once()
