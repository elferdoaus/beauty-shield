
import ipaddress
import socket


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
