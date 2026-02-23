# validators.py
from __future__ import annotations
import ipaddress
from typing import Tuple

def validate_ip(address: str, prefix_len: int = None) -> Tuple[bool, str]:
    try:
        ip = ipaddress.IPv4Address(address)
    except ValueError:
        return False, f"'{address}' is not a valid IPv4 address."

    if prefix_len is not None:
        net = ipaddress.IPv4Network(f"{address}/{prefix_len}", strict=False)
        if ip == net.network_address:
            return False, f"{address} is the network address of {net}."
        if ip == net.broadcast_address:
            return False, f"{address} is the broadcast address of {net}."

    return True, ""

def validate_prefix(prefix_len: int) -> Tuple[bool, str]:
    if not isinstance(prefix_len, int) or not (1 <= prefix_len <= 32):
        return False, f"Prefix length must be 1-32, got {prefix_len}."
    return True, ""

def validate_gateway_in_subnet(
    gateway: str, host_ip: str, prefix_len: int
) -> Tuple[bool, str]:
    try:
        gw = ipaddress.IPv4Address(gateway)
        net = ipaddress.IPv4Network(f"{host_ip}/{prefix_len}", strict=False)
    except ValueError as e:
        return False, str(e)

    if gw not in net:
        return False, f"Gateway {gateway} is not in subnet {net}."
    return True, ""

def validate_dns(address: str) -> Tuple[bool, str]:
    try:
        ipaddress.IPv4Address(address)
        return True, ""
    except ValueError:
        return False, f"'{address}' is not a valid DNS server IP."

def parse_ip_prefix(cidr: str) -> Tuple[str, int]:
    """Parse '192.168.1.0/24' -> ('192.168.1.0', 24). Raises ValueError on bad input."""
    net = ipaddress.IPv4Network(cidr, strict=False)
    return str(net.network_address), net.prefixlen
