
import requests
from urllib.parse import urlparse


def scan_url(url):
    issues = []

    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    parsed = urlparse(url)

    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        issues.append({
            "type": "INVALID_URL",
            "severity": "HIGH",
            "message": "Invalid URL",
            "recommendation": "Enter a valid HTTP or HTTPS URL."
        })
        return issues

    if parsed.scheme == "http":
        issues.append({
            "type": "HTTPS",
            "severity": "HIGH",
            "message": "The URL does not use HTTPS",
            "recommendation": "Use HTTPS to encrypt communications."
        })

    try:
        response = requests.get(
            url,
            timeout=5,
            allow_redirects=True
        )

        security_headers = {
            "Content-Security-Policy": {
                "severity": "HIGH",
                "recommendation": "Configure a Content-Security-Policy header."
            },
            "X-Content-Type-Options": {
                "severity": "MEDIUM",
                "recommendation": "Set X-Content-Type-Options to nosniff."
            },
            "X-Frame-Options": {
                "severity": "MEDIUM",
                "recommendation": "Configure X-Frame-Options or CSP frame-ancestors."
            },
            "Strict-Transport-Security": {
                "severity": "MEDIUM",
                "recommendation": "Enable HSTS on HTTPS websites."
            }
        }

        for header in security_headers:
            if header == "Strict-Transport-Security":
                if not response.url.startswith("https://"):
                    continue

            if header == "X-Frame-Options":
                csp = response.headers.get(
                    "Content-Security-Policy", ""
                )
                if "frame-ancestors" in csp.lower():
                    continue

            if header not in response.headers:
                issues.append({
                    "type": "MISSING_HEADER",
                    "header": header,
                    "severity": security_headers[header]["severity"],
                    "message": "Missing security header: " + header,
                    "recommendation": security_headers[header]["recommendation"]
                })

        for cookie in response.cookies:
            if not cookie.secure:
                issues.append({
                    "type": "INSECURE_COOKIE",
                    "severity": "HIGH",
                    "message": "Cookie without Secure: " + cookie.name,
                    "recommendation": "Enable the Secure attribute."
                })

            if not cookie.has_nonstandard_attr("HttpOnly"):
                issues.append({
                    "type": "INSECURE_COOKIE",
                    "severity": "MEDIUM",
                    "message": "Cookie without HttpOnly: " + cookie.name,
                    "recommendation": "Enable HttpOnly when JavaScript access is unnecessary."
                })

            if not cookie.has_nonstandard_attr("SameSite"):
                issues.append({
                    "type": "INSECURE_COOKIE",
                    "severity": "MEDIUM",
                    "message": "Cookie without SameSite: " + cookie.name,
                    "recommendation": "Configure SameSite=Lax or Strict where appropriate."
                })

    except requests.RequestException:
        issues.append({
            "type": "CONNECTION_ERROR",
            "severity": "HIGH",
            "message": "Unable to connect to the website",
            "recommendation": "Check that the URL is valid and reachable."
        })

    return issues
