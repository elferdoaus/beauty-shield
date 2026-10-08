
import pytest
import urllib3

from unittest.mock import MagicMock, patch

from app.scanner import scan_url


def make_response(status=200, headers=None, cookies=None):
    if headers is None:
        headers = {}

    response_headers = urllib3.HTTPHeaderDict()

    for name, value in headers.items():
        response_headers.add(name, value)

    if cookies is not None:
        for cookie in cookies:
            response_headers.add("Set-Cookie", cookie)

    response = MagicMock()
    response.status = status
    response.headers = response_headers

    return response


def test_missing_security_headers():
    response = make_response()

    with patch("app.scanner.safe_get", return_value=response):
        issues = scan_url("https://example.com")

    headers = [
        issue["header"]
        for issue in issues
        if issue["type"] == "MISSING_HEADER"
    ]

    assert "Content-Security-Policy" in headers
    assert "X-Content-Type-Options" in headers
    assert "X-Frame-Options" in headers
    assert "Strict-Transport-Security" in headers


def test_http_detection():
    issues = scan_url("http://example.com")

    assert any(
        issue["type"] == "HTTPS"
        for issue in issues
    )


def test_cookie_without_secure():
    response = make_response(
        cookies=[
            "session=abc; HttpOnly; SameSite=Lax"
        ]
    )

    with patch("app.scanner.safe_get", return_value=response):
        issues = scan_url("https://example.com")

    assert any(
        issue["type"] == "INSECURE_COOKIE"
        and "Secure" in issue["message"]
        for issue in issues
    )


def test_cookie_without_httponly():
    response = make_response(
        cookies=[
            "session=abc; Secure; SameSite=Lax"
        ]
    )

    with patch("app.scanner.safe_get", return_value=response):
        issues = scan_url("https://example.com")

    assert any(
        issue["type"] == "INSECURE_COOKIE"
        and "HttpOnly" in issue["message"]
        for issue in issues
    )


def test_cookie_without_samesite():
    response = make_response(
        cookies=[
            "session=abc; Secure; HttpOnly"
        ]
    )

    with patch("app.scanner.safe_get", return_value=response):
        issues = scan_url("https://example.com")

    assert any(
        issue["type"] == "INSECURE_COOKIE"
        and "SameSite" in issue["message"]
        for issue in issues
    )


def test_redirect_not_followed():
    response = make_response(
        status=302,
        headers={
            "Location": "http://127.0.0.1"
        }
    )

    with patch(
        "app.scanner.safe_get",
        return_value=response
    ) as mock_get:
        issues = scan_url("https://example.com")

    assert any(
        issue["type"] == "REDIRECT"
        for issue in issues
    )

    mock_get.assert_called_once_with(
        "https://example.com"
    )


def test_multiple_cookies():
    response = make_response(
        cookies=[
            "session=abc; Secure; HttpOnly; SameSite=Lax",
            "preferences=dark"
        ]
    )

    with patch("app.scanner.safe_get", return_value=response):
        issues = scan_url("https://example.com")

    insecure_cookies = [
        issue
        for issue in issues
        if issue["type"] == "INSECURE_COOKIE"
    ]

    assert len(insecure_cookies) == 3

    assert all(
        "preferences" in issue["message"]
        for issue in insecure_cookies
    )


def test_connection_error():
    with patch(
        "app.scanner.safe_get",
        side_effect=urllib3.exceptions.HTTPError(
            "Connection failed"
        )
    ):
        issues = scan_url("https://example.com")

    assert any(
        issue["type"] == "CONNECTION_ERROR"
        for issue in issues
    )


def test_secure_headers():
    response = make_response(
        headers={
            "Content-Security-Policy": "default-src 'self'; frame-ancestors 'none'",
            "X-Content-Type-Options": "nosniff",
            "Strict-Transport-Security": "max-age=31536000"
        }
    )

    with patch("app.scanner.safe_get", return_value=response):
        issues = scan_url("https://example.com")

    assert not any(
        issue["type"] == "MISSING_HEADER"
        for issue in issues
    )
