import requests


def scan_url(url):
    issues = []

    if not url.startswith("https://"):
        issues.append({
            "type": "HTTPS",
            "severity": "HIGH",
            "message": "The website does not use HTTPS"
        })

    try:
        response = requests.get(url, timeout=5)

        security_headers = {
            "Content-Security-Policy": "HIGH",
            "X-Content-Type-Options": "MEDIUM",
            "X-Frame-Options": "MEDIUM"
        }

        for header in security_headers:
            if header not in response.headers:
                issues.append({
                    "type": "MISSING_HEADER",
                    "severity": security_headers[header],
                    "message": "Missing security header: " + header
                })

    except requests.RequestException:
        issues.append({
            "type": "CONNECTION_ERROR",
            "severity": "HIGH",
            "message": "Unable to connect to the website"
        })

    return issues