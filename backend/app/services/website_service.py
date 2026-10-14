"""
Websites (spec §7–8, task 023): domains, the install snippet, Origin checks and
verification.

A website is verified when either
  (a) the tracker sends an event whose Origin (or Referer) host is the website's
      domain, one of its subdomains, or an extra allowed domain, or
  (b) its home page contains the snippet with the site token, or a
      <meta name="clickshield-verification" content="<token>"> tag.

Token rotation invalidates the old token immediately (no grace period): a token
is public (it is in the page HTML), so rotation is used when it is being abused,
and a grace period would keep the abuse working. Install the new snippet first.

Verification fetches are SSRF-guarded: only http(s), every resolved address must
be public, redirects are followed manually (max 3) and re-checked, the body is
capped at WEBSITE_VERIFY_MAX_BYTES.
"""
from __future__ import annotations

import asyncio
import ipaddress
import re
import socket
from dataclasses import dataclass
from html import escape
from urllib.parse import urljoin, urlsplit

import httpx

from app.core.config import settings
from app.models import Website

DOMAIN_RE = re.compile(r"^(?=.{1,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)(\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*$")
MAX_REDIRECTS = 3


def normalize_domain(value: str) -> str:
    """'HTTPS://Www.Exämple.com:443/path' → 'www.xn--exmple-cua.com'. Raises ValueError."""
    raw = (value or "").strip().lower()
    if "://" not in raw:
        raw = "//" + raw
    host = (urlsplit(raw).hostname or "").rstrip(".")
    if not host:
        raise ValueError("Enter a domain such as example.com")
    try:
        host = host.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise ValueError(f"Invalid domain: {value!r}") from exc
    try:
        ipaddress.ip_address(host)
    except ValueError:
        pass
    else:
        raise ValueError("Use the website's domain name, not an IP address")
    if not DOMAIN_RE.match(host):
        raise ValueError(f"Invalid domain: {value!r}")
    return host


def host_of(url_or_origin: str | None) -> str | None:
    if not url_or_origin or url_or_origin == "null":
        return None
    try:
        host = urlsplit(url_or_origin.strip()).hostname
    except ValueError:
        return None
    if not host:
        return None
    try:
        return host.rstrip(".").encode("idna").decode("ascii").lower()
    except UnicodeError:
        return host.lower()


def host_allowed(website: Website, host: str | None) -> bool:
    """The website's domain, any of its subdomains, or an explicitly allowed host."""
    if not host:
        return False
    domain = website.domain.lower()
    if host == domain or host.endswith("." + domain):
        return True
    return host in {d.lower() for d in (website.allowed_domains or [])}


def snippet(website: Website) -> str:
    """The install snippet (spec §8, task 024 data-site-id style). Built server-side only."""
    base = settings.TRACKING_SNIPPET_BASE_URL.rstrip("/")
    consent = ' data-require-consent="true"' if website.require_consent else ""
    return (
        f'<script async src="{escape(base)}/track.js" '
        f'data-site-id="{escape(website.tracking_token)}"{consent}></script>'
    )


# ---- verification fetch ---------------------------------------------------------

class UnsafeTarget(ValueError):
    pass


@dataclass(frozen=True)
class VerifyResult:
    verified: bool
    method: str | None
    detail: str


async def _assert_public(host: str, port: int) -> None:
    try:
        infos = await asyncio.get_running_loop().getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise UnsafeTarget(f"{host} does not resolve") from exc
    for info in infos:
        address = ipaddress.ip_address(info[4][0])
        if not address.is_global or address.is_multicast:
            raise UnsafeTarget(f"{host} resolves to a non-public address; refusing to fetch it")


def page_has_tracker(html: str, token: str) -> str | None:
    meta = re.search(
        r'<meta[^>]+name=["\']clickshield-verification["\'][^>]+content=["\']([^"\']+)["\']', html, re.I
    ) or re.search(r'<meta[^>]+content=["\']([^"\']+)["\'][^>]+name=["\']clickshield-verification["\']', html, re.I)
    if meta and meta.group(1).strip() == token:
        return "meta_tag"
    if token in html:
        return "snippet"
    return None


async def fetch_home_page(domain: str, *, transport: httpx.AsyncBaseTransport | None = None) -> str:
    url = f"https://{domain}/"
    async with httpx.AsyncClient(
        timeout=settings.WEBSITE_VERIFY_TIMEOUT_SECONDS, follow_redirects=False, transport=transport,
        headers={"User-Agent": "ClickShield-Verifier/1.0"},
    ) as client:
        for _ in range(MAX_REDIRECTS + 1):
            parts = urlsplit(url)
            if parts.scheme not in {"http", "https"} or not parts.hostname:
                raise UnsafeTarget(f"Refusing to fetch {url}")
            if transport is None:  # tests inject a transport; real fetches are checked
                await _assert_public(parts.hostname, parts.port or (443 if parts.scheme == "https" else 80))
            async with client.stream("GET", url) as response:
                if response.is_redirect and "location" in response.headers:
                    url = urljoin(url, response.headers["location"])
                    continue
                if response.status_code >= 400:
                    raise httpx.HTTPStatusError(f"HTTP {response.status_code}", request=response.request, response=response)
                body = b""
                async for chunk in response.aiter_bytes():
                    body += chunk
                    if len(body) >= settings.WEBSITE_VERIFY_MAX_BYTES:
                        break
                return body[: settings.WEBSITE_VERIFY_MAX_BYTES].decode(response.encoding or "utf-8", errors="replace")
        raise UnsafeTarget("Too many redirects")


async def verify_by_fetch(website: Website, *, transport: httpx.AsyncBaseTransport | None = None) -> VerifyResult:
    try:
        html = await fetch_home_page(website.domain, transport=transport)
    except UnsafeTarget as exc:
        return VerifyResult(False, None, str(exc))
    except httpx.HTTPError as exc:
        return VerifyResult(False, None, f"Could not load https://{website.domain}/ ({exc})")
    method = page_has_tracker(html, website.tracking_token)
    if method is None:
        return VerifyResult(False, None, "The tracking snippet or verification meta tag was not found on the home page.")
    return VerifyResult(True, method, "Tracking snippet found." if method == "snippet" else "Verification meta tag found.")
