
from unittest.mock import Mock, patch

from app.scanner import scan_url


def test_missing_security_headers():
    response = Mock()
    response.status_code = 200
    response.url = "https://example.com"
    response.headers = {}
    response.cookies = []

    with patch("app.scanner.requests.get", return_value=response):
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
    response = Mock()
    response.status_code = 200
    response.url = "http://example.com"
    response.headers = {}
    response.cookies = []

    with patch("app.scanner.requests.get", return_value=response):
        issues = scan_url("http://example.com")

    assert any(
        issue["type"] == "HTTPS"
        for issue in issues
    )


def test_cookie_without_secure():
    response = Mock()
    response.status_code = 200
    response.url = "https://example.com"
    response.headers = {}

    cookie = Mock()
    cookie.name = "session"
    cookie.secure = False
    cookie.has_nonstandard_attr.return_value = True

    response.cookies = [cookie]

    with patch("app.scanner.requests.get", return_value=response):
        issues = scan_url("https://example.com")

    assert any(
        issue["type"] == "INSECURE_COOKIE"
        and "Secure" in issue["message"]
        for issue in issues
    )


def test_cookie_without_httponly():
    response = Mock()
    response.status_code = 200
    response.url = "https://example.com"
    response.headers = {}

    cookie = Mock()
    cookie.name = "session"
    cookie.secure = True

    def check_attribute(name):
        if name == "HttpOnly":
            return False
        return True

    cookie.has_nonstandard_attr.side_effect = check_attribute
    response.cookies = [cookie]

    with patch("app.scanner.requests.get", return_value=response):
        issues = scan_url("https://example.com")

    assert any(
        issue["type"] == "INSECURE_COOKIE"
        and "HttpOnly" in issue["message"]
        for issue in issues
    )


def test_cookie_without_samesite():
    response = Mock()
    response.status_code = 200
    response.url = "https://example.com"
    response.headers = {}

    cookie = Mock()
    cookie.name = "session"
    cookie.secure = True

    def check_attribute(name):
        if name == "SameSite":
            return False
        return True

    cookie.has_nonstandard_attr.side_effect = check_attribute
    response.cookies = [cookie]

    with patch("app.scanner.requests.get", return_value=response):
        issues = scan_url("https://example.com")

    assert any(
        issue["type"] == "INSECURE_COOKIE"
        and "SameSite" in issue["message"]
        for issue in issues
    )


def test_redirect_not_followed():
    response = Mock()
    response.status_code = 302
    response.url = "https://example.com"
    response.headers = {
        "Location": "http://127.0.0.1"
    }
    response.cookies = []

    with patch("app.scanner.requests.get", return_value=response) as mock_get:
        issues = scan_url("https://example.com")

    assert any(
        issue["type"] == "REDIRECT"
        for issue in issues
    )

    assert mock_get.call_args.kwargs["allow_redirects"] is False
