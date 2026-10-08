
from unittest.mock import patch, Mock
from app.scanner import scan_url


def test_missing_security_headers():
    response = Mock()
    response.url = "https://example.com"
    response.headers = {}
    response.cookies = []

    with patch("app.scanner.requests.get", return_value=response):
        issues = scan_url("https://example.com")

    missing = []

    for issue in issues:
        if issue["type"] == "MISSING_HEADER":
            missing.append(issue["header"])

    assert "Content-Security-Policy" in missing
    assert "X-Content-Type-Options" in missing
    assert "X-Frame-Options" in missing
    assert "Strict-Transport-Security" in missing


def test_http_detection():
    response = Mock()
    response.url = "http://example.com"
    response.headers = {}
    response.cookies = []

    with patch("app.scanner.requests.get", return_value=response):
        issues = scan_url("http://example.com")

    found = False

    for issue in issues:
        if issue["type"] == "HTTPS":
            found = True

    assert found is True


def test_cookie_without_secure():
    response = Mock()
    response.url = "https://example.com"
    response.headers = {}

    cookie = Mock()
    cookie.name = "session"
    cookie.secure = False
    cookie.has_nonstandard_attr.return_value = True

    response.cookies = [cookie]

    with patch("app.scanner.requests.get", return_value=response):
        issues = scan_url("https://example.com")

    found = False

    for issue in issues:
        if issue["type"] == "INSECURE_COOKIE":
            if "without Secure" in issue["message"]:
                found = True

    assert found is True


def test_cookie_without_httponly():
    response = Mock()
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

    found = False

    for issue in issues:
        if "without HttpOnly" in issue["message"]:
            found = True

    assert found is True


def test_cookie_without_samesite():
    response = Mock()
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

    found = False

    for issue in issues:
        if "without SameSite" in issue["message"]:
            found = True

    assert found is True
