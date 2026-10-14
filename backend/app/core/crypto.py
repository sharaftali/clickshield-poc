"""
Symmetric encryption for sensitive tokens (Google refresh tokens, spec §63).
Fernet (AES-128-CBC + HMAC-SHA256), with key rotation through MultiFernet (task 032):
the first key of TOKEN_ENCRYPTION_KEYS encrypts, every listed key decrypts.

Generate a key:
    python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"

Rotate: put the new key first (`TOKEN_ENCRYPTION_KEYS=new,old`), deploy, run
`python -m app.cli reencrypt-tokens`, then drop the old key.
"""
from __future__ import annotations

from cryptography.fernet import Fernet, InvalidToken, MultiFernet

from app.core.config import settings

_fernet: MultiFernet | None = None
_keys: tuple[str, ...] = ()


def _get_fernet() -> MultiFernet:
    global _fernet, _keys
    keys = tuple(settings.fernet_keys)
    if _fernet is None or keys != _keys:
        if not keys:
            raise RuntimeError("No token encryption key configured (TOKEN_ENCRYPTION_KEYS).")
        try:
            _fernet = MultiFernet([Fernet(key.encode("utf-8")) for key in keys])
        except Exception as exc:
            raise RuntimeError(
                "Invalid TOKEN_ENCRYPTION_KEYS. Generate a key with:\n"
                "  python -c \"from cryptography.fernet import Fernet; "
                "print(Fernet.generate_key().decode())\""
            ) from exc
        _keys = keys
    return _fernet


def encrypt(plaintext: str) -> str:
    """Encrypt a string with the newest key and return a URL-safe base64 token."""
    if not plaintext:
        raise ValueError("Cannot encrypt empty string")
    return _get_fernet().encrypt(plaintext.encode("utf-8")).decode("utf-8")


def decrypt(ciphertext: str) -> str:
    """Decrypt a token encrypted with any configured key."""
    if not ciphertext:
        raise ValueError("Cannot decrypt empty string")
    try:
        return _get_fernet().decrypt(ciphertext.encode("utf-8")).decode("utf-8")
    except InvalidToken as exc:
        raise ValueError(
            "Failed to decrypt token — key may have rotated or data is corrupt"
        ) from exc


def reencrypt(ciphertext: str) -> str:
    """Re-encrypt with the newest key (MultiFernet.rotate). Raises ValueError if no key fits."""
    try:
        return _get_fernet().rotate(ciphertext.encode("utf-8")).decode("utf-8")
    except InvalidToken as exc:
        raise ValueError("Token was not encrypted with any configured key") from exc
