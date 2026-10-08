
import ipaddress


def check_ip(address):
    try:
        ip = ipaddress.ip_address(address)
        return ip.is_global
    except ValueError:
        return False
