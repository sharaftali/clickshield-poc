"""
Resolve the real client IP for a request.

Per spec §13 / §62: the IP is the key Google Ads exclusions are created for,
so it must not be spoofable. X-Forwarded-For is only honoured when the direct
peer is one of our own trusted proxies, and then the client IP is the
rightmost entry that is NOT a trusted proxy (the leftmost entry is whatever
the caller chose to send).

Deployment note: run uvicorn with --no-proxy-headers. Otherwise uvicorn's own
ProxyHeadersMiddleware (enabled by default, trusting 127.0.0.1) rewrites
request.client from X-Forwarded-For before this code ever sees the request.
"""
from __future__ import annotations

import ipaddress
import logging
from functools import lru_cache
from typing import Iterable

from fastapi import Request

from app.core.config import settings

logger = logging.getLogger(__name__)

IPAddress = ipaddress.IPv4Address | ipaddress.IPv6Address
IPNetwork = ipaddress.IPv4Network | ipaddress.IPv6Network


class ClientIPError(ValueError):
    """The client IP could not be determined or is not a valid IP address."""


@lru_cache(maxsize=8)
def parse_trusted_networks(raw: str) -> tuple[IPNetwork, ...]:
    return tuple(
        ipaddress.ip_network(item.strip(), strict=False)
        for item in raw.split(",")
        if item.strip()
    )


def _parse_ip(value: str) -> IPAddress:
    """Parse an IP, tolerating ports some proxies append, and unwrap IPv4-mapped IPv6."""
    candidate = value.strip()
    if candidate.startswith("["):
        # [2001:db8::1]:443
        candidate = candidate[1:].split("]", 1)[0]
    elif candidate.count(":") == 1:
        # 203.0.113.7:51234
        candidate = candidate.split(":", 1)[0]

    try:
        ip = ipaddress.ip_address(candidate)
    except ValueError as exc:
        raise ClientIPError("Invalid client IP address") from exc

    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        return ip.ipv4_mapped
    return ip


def parse_ip(value: str) -> IPAddress:
    """Public form of the parser: normalized IP, or ClientIPError."""
    return _parse_ip(value)


def _is_trusted(ip: IPAddress, trusted: Iterable[IPNetwork]) -> bool:
    return any(ip.version == net.version and ip in net for net in trusted)


def resolve_client_ip(
    request: Request,
    trusted_networks: tuple[IPNetwork, ...] | None = None,
) -> str:
    """Return the client IP as a normalized string, or raise ClientIPError."""
    if trusted_networks is None:
        trusted_networks = parse_trusted_networks(settings.TRUSTED_PROXY_CIDRS)

    if request.client is None or not request.client.host:
        raise ClientIPError("Unable to determine client IP")
    peer_ip = _parse_ip(request.client.host)

    if not _is_trusted(peer_ip, trusted_networks):
        # Direct connection (or an unknown proxy): the header is caller-controlled.
        return str(peer_ip)

    # Several X-Forwarded-For headers are equivalent to one comma-joined header.
    entries = [
        entry.strip()
        for header in request.headers.getlist("x-forwarded-for")
        for entry in header.split(",")
        if entry.strip()
    ]
    if not entries:
        return str(peer_ip)

    # Walk from the proxy nearest to us back towards the client.
    hop: IPAddress | None = None
    for entry in reversed(entries):
        try:
            hop = _parse_ip(entry)
        except ClientIPError:
            logger.debug("Rejecting request with malformed X-Forwarded-For entry from trusted peer %s", peer_ip)
            raise
        if not _is_trusted(hop, trusted_networks):
            return str(hop)

    # Every hop is one of our own proxies; the leftmost is the closest to the client.
    return str(hop)
