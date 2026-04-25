"""CIDR-whitelist matching helpers."""

from __future__ import annotations

import ipaddress
from typing import Iterable


def parse_cidr(text: str) -> ipaddress._BaseNetwork:
    """Parse a user-supplied CIDR or bare address. Raises ValueError."""
    # strict=False lets "192.168.1.10/24" work (host bits set) without
    # forcing the operator to compute the network address by hand.
    return ipaddress.ip_network(text.strip(), strict=False)


def ip_matches_any(ip: str, cidrs: Iterable[str]) -> bool:
    """True iff `ip` falls inside any of the supplied CIDR strings."""
    if not ip:
        return False
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    for c in cidrs:
        try:
            net = parse_cidr(c)
        except ValueError:
            continue
        # ip_address / ip_network must be the same family for `in` to work.
        if isinstance(addr, ipaddress.IPv4Address) and isinstance(
            net, ipaddress.IPv4Network
        ):
            if addr in net:
                return True
        elif isinstance(addr, ipaddress.IPv6Address) and isinstance(
            net, ipaddress.IPv6Network
        ):
            if addr in net:
                return True
    return False
