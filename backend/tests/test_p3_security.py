"""P3 unit tests: secrets (032), RBAC route audit (030), admin schemas (027), CORS / headers /
rate limiter (031), websites (023)."""
from __future__ import annotations

import inspect

import httpx
import pytest
from cryptography.fernet import Fernet
from fastapi.routing import APIRoute
from pydantic import BaseModel

from app.api import admin as admin_api
from app.core import crypto, rate_limit
from app.core.config import Settings, settings
from app.main import app
from app.models import Website
from app.services import website_service
from app.services.website_service import host_allowed, normalize_domain, page_has_tracker, snippet

# Stand-ins for values that were once committed (the real ones stay out of the repo, task 032).
LEAKED_SECRET = "a-leaked-secret-value-that-is-long-enough-for-jwt"
LEAKED_FERNET = Fernet.generate_key().decode()
GOOD = {"SECRET_KEY": "x" * 48, "TOKEN_ENCRYPTION_KEYS": Fernet.generate_key().decode(),
        "API_CORS_ORIGINS": "https://app.example.com"}


def make_settings(**values) -> Settings:
    return Settings(_env_file=None, **values)


# ---- task 032: secrets ---------------------------------------------------------------

@pytest.mark.parametrize(
    ("overrides", "message"),
    [
        ({"SECRET_KEY": ""}, "SECRET_KEY is not set"),
        ({"SECRET_KEY": "short"}, "at least 32 bytes"),
        ({"SECRET_KEY": LEAKED_SECRET}, "committed to the repository"),
        ({"TOKEN_ENCRYPTION_KEYS": ""}, "TOKEN_ENCRYPTION_KEYS"),
        ({"TOKEN_ENCRYPTION_KEYS": LEAKED_FERNET}, "committed to the repository"),
        ({"TOKEN_ENCRYPTION_KEYS": "not-a-key"}, "not a valid Fernet key"),
        ({"GOOGLE_CLIENT_ID": "id", "GOOGLE_CLIENT_SECRET": ""}, "GOOGLE_CLIENT_SECRET is required"),
        ({"API_CORS_ORIGINS": "*"}, "never allowed"),
    ],
)
def test_production_refuses_missing_weak_or_leaked_secrets(overrides, message, monkeypatch):
    from app.core import config as config_module

    monkeypatch.setattr(config_module, "COMPROMISED_SECRET_HASHES", config_module.COMPROMISED_SECRET_HASHES | {
        config_module._sha256(LEAKED_SECRET), config_module._sha256(LEAKED_FERNET)})
    with pytest.raises(ValueError, match=message):
        make_settings(ENVIRONMENT="production", **{**GOOD, **overrides})


def test_production_starts_with_real_secrets():
    configured = make_settings(ENVIRONMENT="production", **GOOD)
    assert not configured.is_development and len(configured.fernet_keys) == 1


def test_development_generates_ephemeral_secrets_with_a_warning():
    from app.core import config as config_module

    config_module.STARTUP_WARNINGS.clear()
    dev = make_settings(ENVIRONMENT="development", SECRET_KEY="", TOKEN_ENCRYPTION_KEYS="", TOKEN_ENCRYPTION_KEY="")
    assert len(dev.SECRET_KEY) >= 32 and len(dev.fernet_keys) == 1
    assert any("random key" in w for w in config_module.STARTUP_WARNINGS)


def test_no_secret_defaults_in_code():
    fields = Settings.model_fields
    for name in ("SECRET_KEY", "TOKEN_ENCRYPTION_KEY", "TOKEN_ENCRYPTION_KEYS", "DEFAULT_ADMIN_PASSWORD", "SMTP_PASSWORD"):
        assert fields[name].default == "", name


def test_key_rotation(monkeypatch):
    key_a, key_b = Fernet.generate_key().decode(), Fernet.generate_key().decode()
    monkeypatch.setattr(settings, "TOKEN_ENCRYPTION_KEYS", key_a)
    token = crypto.encrypt("refresh-token")
    monkeypatch.setattr(settings, "TOKEN_ENCRYPTION_KEYS", f"{key_b},{key_a}")
    assert crypto.decrypt(token) == "refresh-token"            # old key still decrypts
    rotated = crypto.reencrypt(token)
    monkeypatch.setattr(settings, "TOKEN_ENCRYPTION_KEYS", key_b)
    assert crypto.decrypt(rotated) == "refresh-token"          # works after dropping the old key
    with pytest.raises(ValueError):
        crypto.decrypt(token)


# ---- task 030: every mutating route needs a permission -------------------------------

PUBLIC_MUTATIONS = {
    ("POST", "/api/v1/auth/register"), ("POST", "/api/v1/auth/login"), ("POST", "/api/v1/auth/refresh"),
    ("POST", "/api/v1/auth/accept-invite"), ("POST", "/api/v1/track"),
}


def _permissions(dependant) -> set[str]:
    found = set()
    for dep in dependant.dependencies:
        permission = getattr(dep.call, "permission", None)
        if permission:
            found.add(permission)
        found |= _permissions(dep)
    return found


def test_every_mutating_route_has_a_permission_dependency():
    unprotected = []
    for route in app.routes:
        if not isinstance(route, APIRoute):
            continue
        for method in route.methods - {"GET", "HEAD", "OPTIONS"}:
            if (method, route.path) in PUBLIC_MUTATIONS:
                continue
            if not _permissions(route.dependant):
                unprotected.append(f"{method} {route.path}")
    assert unprotected == []


def test_admin_routes_all_require_platform_admin():
    for route in app.routes:
        if isinstance(route, APIRoute) and route.path.startswith("/api/v1/admin"):
            assert "platform:admin" in _permissions(route.dependant), route.path


# ---- task 027: no credential material in admin responses -------------------------------

FORBIDDEN = ("token", "secret", "password", "encrypted", "credential")


def _fields(model: type[BaseModel], seen=None) -> set[str]:
    seen = seen or set()
    if model in seen:
        return set()
    seen.add(model)
    names = set()
    for name, field in model.model_fields.items():
        names.add(name)
        for arg in getattr(field.annotation, "__args__", ()) + (field.annotation,):
            if inspect.isclass(arg) and issubclass(arg, BaseModel):
                names |= _fields(arg, seen)
    return names


def test_admin_response_models_carry_no_credentials():
    models = [obj for obj in vars(admin_api).values() if inspect.isclass(obj) and issubclass(obj, BaseModel)]
    for route in app.routes:
        if isinstance(route, APIRoute) and route.path.startswith("/api/v1/admin") and route.response_model:
            model = route.response_model
            models += list(getattr(model, "__args__", ())) or [model]
    for model in models:
        if inspect.isclass(model) and issubclass(model, BaseModel):
            for name in _fields(model):
                assert not any(word in name.lower() for word in FORBIDDEN), f"{model.__name__}.{name}"


# ---- task 031: CORS split, headers, fail-open limiter ----------------------------------

async def _client():
    return httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test")


async def test_dashboard_api_rejects_unlisted_origins_but_tracking_accepts_any():
    preflight = {"access-control-request-method": "GET", "access-control-request-headers": "authorization"}
    async with await _client() as client:
        evil = await client.options("/api/v1/dashboard/overview", headers={"origin": "https://evil.test", **preflight})
        track = await client.options("/api/v1/track", headers={
            "origin": "https://customer-shop.test", "access-control-request-method": "POST",
            "access-control-request-headers": "content-type"})
        allowed_origin = settings.API_CORS_ORIGINS.split(",")[0].strip()
        ok = await client.options("/api/v1/dashboard/overview", headers={"origin": allowed_origin, **preflight})
    assert "access-control-allow-origin" not in evil.headers
    assert track.headers.get("access-control-allow-origin") in ("*", "https://customer-shop.test")
    assert "access-control-allow-credentials" not in track.headers
    assert ok.headers.get("access-control-allow-origin") == allowed_origin


async def test_security_headers_and_cached_script():
    async with await _client() as client:
        response = await client.get("/track.js")
        again = await client.get("/track.js", headers={"if-none-match": response.headers["etag"]})
        health = await client.get("/health")
    assert response.status_code == 200 and "javascript" in response.headers["content-type"]
    assert "max-age" in response.headers["cache-control"] and again.status_code == 304
    assert health.headers["x-content-type-options"] == "nosniff"
    assert health.headers["x-frame-options"] == "DENY"
    assert "strict-transport-security" not in health.headers  # plain HTTP


async def test_rate_limiter_counts_and_fails_open(fake_redis):
    results = [await rate_limit.hit("unit:key", 3, 60) for _ in range(4)]
    assert [r.allowed for r in results] == [True, True, True, False] and results[-1].retry_after >= 1
    fake_redis.down = True
    assert (await rate_limit.hit("unit:key", 3, 60)).allowed is True


async def test_track_rejects_huge_bodies_before_parsing():
    async with await _client() as client:
        response = await client.post("/api/v1/track", content=b"{" + b" " * 2_000_000,
                                     headers={"content-type": "application/json"})
    assert response.status_code == 413


# ---- task 023: domains, origin, snippet, SSRF ----------------------------------------

@pytest.mark.parametrize(("raw", "clean"), [
    ("HTTPS://Www.Example.com:443/path?q=1", "www.example.com"),
    ("example.com", "example.com"),
    ("bücher.de", "xn--bcher-kva.de"),
    ("localhost", "localhost"),
])
def test_normalize_domain(raw, clean):
    assert normalize_domain(raw) == clean


@pytest.mark.parametrize("raw", ["", "10.0.0.1", "exa mple.com", "-bad-.com"])
def test_normalize_domain_rejects(raw):
    with pytest.raises(ValueError):
        normalize_domain(raw)


def test_host_allowed_covers_subdomains_and_extra_domains():
    site = Website(domain="example.test", allowed_domains=["shop-partner.test"], tracking_token="t" * 20)
    assert host_allowed(site, "example.test") and host_allowed(site, "www.example.test")
    assert host_allowed(site, "shop-partner.test")
    assert not host_allowed(site, "evil.test") and not host_allowed(site, "example.test.evil.test")
    assert not host_allowed(site, None)


def test_snippet_and_page_detection():
    site = Website(domain="example.test", tracking_token="tok_abcdefghijklmnop", require_consent=True)
    html = snippet(site)
    assert 'data-site-id="tok_abcdefghijklmnop"' in html and 'data-require-consent="true"' in html
    assert html.startswith("<script async src=") and "/track.js" in html
    assert page_has_tracker(f"<html>{html}</html>", site.tracking_token) == "snippet"
    meta = '<meta name="clickshield-verification" content="tok_abcdefghijklmnop">'
    assert page_has_tracker(meta, site.tracking_token) == "meta_tag"
    assert page_has_tracker("<html></html>", site.tracking_token) is None


async def test_verification_fetch_refuses_private_addresses():
    with pytest.raises(website_service.UnsafeTarget):
        await website_service._assert_public("127.0.0.1", 443)
    site = Website(domain="localhost", tracking_token="t" * 20)
    result = await website_service.verify_by_fetch(site)
    assert result.verified is False and "non-public" in result.detail


async def test_verification_by_meta_tag_with_mocked_fetch():
    site = Website(domain="example.test", tracking_token="tok_abcdefghijklmnop")

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/":
            return httpx.Response(301, headers={"location": "https://www.example.test/home"})
        return httpx.Response(200, text='<meta name="clickshield-verification" content="tok_abcdefghijklmnop">')

    result = await website_service.verify_by_fetch(site, transport=httpx.MockTransport(handler))
    assert result.verified and result.method == "meta_tag"
