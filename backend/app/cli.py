"""
Operator commands (tasks 027, 029, 032):

    python -m app.cli create-admin --email owner@client.com --organization "Client Inc"
        Password from $CLICKSHIELD_ADMIN_PASSWORD, else prompted. There is no default password.
    python -m app.cli grant-platform-admin --email staff@clickshield.com [--revoke]
        Platform admin can only be granted here, never through the API.
    python -m app.cli reencrypt-tokens
        Re-encrypt every Google refresh token with the first key of TOKEN_ENCRYPTION_KEYS.
    python -m app.cli retention [--apply]
        Run the retention job now (dry run unless --apply).
    python -m app.cli google-smoke --connection-id <id> --campaign-id <id> [--ip 203.0.113.7] [--cleanup]
        Live check against a Google Ads TEST account (needs GOOGLE_ADS_DRY_RUN=false). Exit code 0/1/2.
"""
from __future__ import annotations

import argparse
import asyncio
import getpass
import os
import re
import sys

from sqlalchemy import select

from app.core.crypto import reencrypt
from app.core.database import AsyncSessionLocal
from app.core.security import hash_password
from app.models import GoogleConnection, Organization, ProtectionMode, User, UserRole


def _password() -> str:
    password = os.environ.get("CLICKSHIELD_ADMIN_PASSWORD") or getpass.getpass("Password: ")
    if len(password) < 12 or not re.search(r"\d", password) or not re.search(r"[A-Za-z]", password):
        sys.exit("The password needs at least 12 characters, with letters and digits.")
    return password


async def create_admin(email: str, organization_name: str, full_name: str | None) -> None:
    email = email.strip().lower()
    async with AsyncSessionLocal() as db:
        if await db.scalar(select(User.id).where(User.email == email)):
            sys.exit(f"{email} already exists.")
        slug = re.sub(r"[^a-z0-9]+", "-", organization_name.lower()).strip("-") or "organization"
        organization = (await db.execute(select(Organization).where(Organization.slug == slug))).scalar_one_or_none()
        if organization is None:
            organization = Organization(name=organization_name, slug=slug, protection_mode=ProtectionMode.BALANCED)
            db.add(organization)
            await db.flush()
        db.add(User(organization_id=organization.id, email=email, hashed_password=hash_password(_password()),
                    full_name=full_name or email, role=UserRole.OWNER))
        await db.commit()
    print(f"Created owner {email} in organization {organization_name!r}.")


async def grant_platform_admin(email: str, revoke: bool) -> None:
    async with AsyncSessionLocal() as db:
        user = (await db.execute(select(User).where(User.email == email.strip().lower()))).scalar_one_or_none()
        if user is None:
            sys.exit(f"No user {email}.")
        user.is_platform_admin = not revoke
        await db.commit()
    print(f"{email}: platform admin {'revoked' if revoke else 'granted'}.")


async def reencrypt_tokens() -> None:
    changed = failed = 0
    async with AsyncSessionLocal() as db:
        for connection in (await db.execute(select(GoogleConnection))).scalars():
            try:
                connection.refresh_token_encrypted = reencrypt(connection.refresh_token_encrypted)
                changed += 1
            except ValueError:
                failed += 1
                print(f"Connection {connection.id}: not decryptable with any configured key", file=sys.stderr)
        await db.commit()
    print(f"Re-encrypted {changed} token(s) with the newest key; {failed} failed.")
    if failed:
        sys.exit(1)


async def retention(apply: bool) -> None:
    from app.workers.retention import run_retention

    print(await run_retention(AsyncSessionLocal, dry_run=not apply))


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(prog="python -m app.cli")
    commands = parser.add_subparsers(dest="command", required=True)
    p = commands.add_parser("create-admin", help="create an organization owner")
    p.add_argument("--email", required=True)
    p.add_argument("--organization", required=True)
    p.add_argument("--name")
    p = commands.add_parser("grant-platform-admin", help="grant / revoke Click Shield staff access")
    p.add_argument("--email", required=True)
    p.add_argument("--revoke", action="store_true")
    commands.add_parser("reencrypt-tokens", help="re-encrypt Google tokens with the newest key")
    p = commands.add_parser("retention", help="run data retention now")
    p.add_argument("--apply", action="store_true", help="really delete / anonymize (default: dry run)")
    p = commands.add_parser("google-smoke", help="live Google Ads check: list, add, read back, remove an IP exclusion")
    p.add_argument("--connection-id", required=True, help="google_connections.id")
    p.add_argument("--campaign-id", required=True, help="Google campaign id (digits) or a Click Shield campaign row id")
    p.add_argument("--ip", default="203.0.113.7", help="IP to exclude (default: TEST-NET-3 documentation address)")
    p.add_argument("--cleanup", action="store_true", help="remove the exclusion again")
    p.add_argument("--customer-id", help="use this customer instead of the connection's (the manager is looked up)")
    args = parser.parse_args(argv)

    if args.command == "create-admin":
        asyncio.run(create_admin(args.email, args.organization, args.name))
    elif args.command == "grant-platform-admin":
        asyncio.run(grant_platform_admin(args.email, args.revoke))
    elif args.command == "reencrypt-tokens":
        asyncio.run(reencrypt_tokens())
    elif args.command == "retention":
        asyncio.run(retention(args.apply))
    elif args.command == "google-smoke":
        from app.services.google_smoke import run_smoke

        sys.exit(asyncio.run(run_smoke(
            args.connection_id, args.campaign_id, ip=args.ip, cleanup=args.cleanup, customer_id=args.customer_id,
        )))


if __name__ == "__main__":
    main()
