"""
Geography helpers for the GEO rules (spec §18, task 018). Pure functions, no I/O
except reading the bundled tz database once.

- `timezone_countries`: IANA timezone → ISO country codes, from tzdata's
  zone.tab / zone1970.tab (static, no external call).
- `match_campaign_geo`: how a visitor's country / region relates to a campaign's
  location targets.
"""
from __future__ import annotations

from dataclasses import dataclass
from functools import lru_cache
from importlib import resources


@lru_cache(maxsize=1)
def _timezone_table() -> dict[str, frozenset[str]]:
    table: dict[str, set[str]] = {}
    try:
        base = resources.files("tzdata").joinpath("zoneinfo")
        for filename in ("zone.tab", "zone1970.tab"):
            for line in base.joinpath(filename).read_text(encoding="utf-8").splitlines():
                if not line or line.startswith("#"):
                    continue
                parts = line.split("\t")
                if len(parts) < 3:
                    continue
                for code in parts[0].split(","):
                    table.setdefault(parts[2], set()).add(code.strip().upper())
    except (ModuleNotFoundError, FileNotFoundError):  # tzdata missing: the rule just never applies
        return {}
    return {zone: frozenset(codes) for zone, codes in table.items()}


def timezone_countries(timezone: str | None) -> frozenset[str] | None:
    """Countries that use this IANA zone; None when unknown (UTC, Etc/*, typos, aliases)."""
    if not timezone:
        return None
    return _timezone_table().get(timezone.strip())


@dataclass(frozen=True)
class GeoTarget:
    country_code: str | None
    region: str | None
    name: str | None
    target_type: str | None   # Country, State, City, … (Google's geo_target_constant.target_type)
    negative: bool = False

    @property
    def is_country_level(self) -> bool:
        return (self.target_type or "").casefold() == "country"


@dataclass(frozen=True)
class GeoMatch:
    kind: str          # "excluded_location" | "outside_countries" | "outside_regions"
    detail: str


def _same(a: str | None, b: str | None) -> bool:
    return bool(a) and bool(b) and a.strip().casefold() == b.strip().casefold()


def _matches(target: GeoTarget, country: str, region: str | None, city: str | None) -> bool:
    if not _same(target.country_code, country):
        return False
    if target.is_country_level or not target.target_type:
        return True
    return _same(target.region, region) or _same(target.name, region) or _same(target.name, city)


def match_campaign_geo(
    targets: list[GeoTarget],
    *,
    country: str | None,
    region: str | None = None,
    city: str | None = None,
) -> GeoMatch | None:
    """None = consistent with targeting, or nothing to compare (no targets / no country)."""
    if not targets or not country:
        return None

    for target in targets:
        if target.negative and _matches(target, country, region, city):
            return GeoMatch("excluded_location", f"visitor location {country} is excluded by the campaign ({target.name})")

    positive = [target for target in targets if not target.negative and target.country_code]
    if not positive:
        return None
    if not any(_same(target.country_code, country) for target in positive):
        targeted = ", ".join(sorted({t.country_code.upper() for t in positive}))
        return GeoMatch("outside_countries", f"visitor country {country} is not targeted ({targeted})")

    in_country = [target for target in positive if _same(target.country_code, country)]
    if any(target.is_country_level for target in in_country):
        return None
    if not region:  # IP data not precise enough to compare regions
        return None
    if any(_matches(target, country, region, city) for target in in_country):
        return None
    names = ", ".join(sorted({t.name or t.region or "?" for t in in_country}))
    return GeoMatch("outside_regions", f"visitor region {region} is outside the targeted areas ({names})")
