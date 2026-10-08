
import ipaddress
import socket
import urllib3
import certifi

from urllib.parse import urlsplit

from app.security import validate_url


def check_ip(address):
    try:
        ip = ipaddress.ip_address(address)
        return ip.is_global
    except ValueError:
        return False


def resolve_public_ips(hostname, port):
    addresses = socket.getaddrinfo(
        hostname,
        port,
        type=socket.SOCK_STREAM
    )

    public_ips = []

    for address in addresses:
        ip = address[4][0]

        if not check_ip(ip):
            raise ValueError("Private or restricted IP address")

        if ip not in public_ips:
            public_ips.append(ip)

    if not public_ips:
        raise ValueError("No public IP address found")

    return public_ips


def safe_get(url):
    if not validate_url(url):
        raise ValueError("URL not allowed")

    parsed = urlsplit(url)

    if parsed.scheme != "https":
        raise ValueError("Only HTTPS is supported")

    if not parsed.hostname:
        raise ValueError("Invalid hostname")

    hostname = parsed.hostname
    port = parsed.port or 443

    ips = resolve_public_ips(hostname, port)
    ip = ips[0]

    connection = urllib3.HTTPSConnectionPool(
        host=ip,
        port=port,
        assert_hostname=hostname,
        server_hostname=hostname,
        cert_reqs="CERT_REQUIRED",
        ca_certs=certifi.where(),
        maxsize=1
    )

    response = None

    try:
        path = parsed.path or "/"

        if parsed.query:
            path = path + "?" + parsed.query

        response = connection.request(
            "GET",
            path,
            headers={"Host": hostname},
            redirect=False,
            retries=False,
            preload_content=False,
            timeout=urllib3.Timeout(
                connect=3,
                read=5
            )
        )

        result = urllib3.HTTPResponse(
            status=response.status,
            headers=response.headers,
            preload_content=False
        )

        return result

    finally:
        if response is not None:
            response.close()

        connection.close()
