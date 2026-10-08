
import ipaddress
import socket
from urllib.parse import urlsplit


ALLOWED_HOSTS = {
    "example.com",
    "www.example.com",
}


def validate_url(url):
    if not isinstance(url, str):
        return False

    if len(url) > 2048:
        return False

    try:
        parsed = urlsplit(url)

        if parsed.scheme not in ("http", "https"):
            return False

        if not parsed.hostname:
            return False

        if parsed.username or parsed.password:
            return False

        if parsed.port not in (None, 80, 443):
            return False

        hostname = parsed.hostname.lower().rstrip(".")

        if hostname not in ALLOWED_HOSTS:
            return False

        if hostname == "localhost":
            return False

        if hostname.endswith(".localhost"):
            return False

        if hostname.endswith(".local"):
            return False

        addresses = socket.getaddrinfo(
            hostname,
            parsed.port or (443 if parsed.scheme == "https" else 80),
            type=socket.SOCK_STREAM
        )

        if not addresses:
            return False

        for address in addresses:
            ip = ipaddress.ip_address(address[4][0])

            if not ip.is_global:
                return False

        return True

    except (ValueError, OSError, UnicodeError):
        return False
