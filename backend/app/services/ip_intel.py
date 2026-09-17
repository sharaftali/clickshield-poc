from __future__ import annotations

import httpx

from app.core.config import settings


class IPIntelService:
    """
    Wraps IPinfo (or any provider). Returns a dict with geo/ASN/VPN flags.
    Cached in-memory for POC. Move to Redis cache in Phase 2.
    """

    def __init__(self):
        self._cache: dict[str, dict] = {}

    async def lookup(self, ip: str) -> dict:
        if ip in self._cache:
            return self._cache[ip]

        if not settings.IPINFO_API_KEY:
            # No API key — return empty enrichment (safe fallback)
            return {}

        url = f"https://ipinfo.io/{ip}/json"
        params = {"token": settings.IPINFO_API_KEY}

        try:
            async with httpx.AsyncClient(timeout=settings.IPINFO_TIMEOUT_SECONDS) as client:
                resp = await client.get(url, params=params)
                resp.raise_for_status()
                data = resp.json()
        except Exception:
            # Fail open — never block traffic because IP intel failed
            return {}

        result = {
            "country": data.get("country"),
            "region": data.get("region"),
            "city": data.get("city"),
            "asn": data.get("org", "").split()[0] if data.get("org") else None,
            "isp": data.get("org"),
            # IPinfo's privacy detection (requires paid plan)
            "is_vpn": bool(data.get("privacy", {}).get("vpn")),
            "is_proxy": bool(data.get("privacy", {}).get("proxy")),
            "is_tor": bool(data.get("privacy", {}).get("tor")),
            "is_datacenter": bool(data.get("privacy", {}).get("hosting")),
        }

        self._cache[ip] = result
        return result
