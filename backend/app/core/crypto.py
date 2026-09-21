"""
Symmetric encryption for sensitive tokens (Google refresh tokens).
Uses Fernet (AES-128 in CBC mode with HMAC-SHA256 for authentication).

Generate a key once:
    python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"

Then put it in .env as TOKEN_ENCRYPTION_KEY.
"""
from __future__ import annotations

from cryptography.fernet import Fernet, InvalidToken

from app.core.config import settings


_fernet: Fernet | None = None


def _get_fernet() -> Fernet:
    global _fernet
    if _fernet is None:
        try:
            _fernet = Fernet(settings.TOKEN_ENCRYPTION_KEY.encode("utf-8"))
        except Exception as exc:
            raise RuntimeError(
                "Invalid TOKEN_ENCRYPTION_KEY. Generate one with:\n"
                "  python -c \"from cryptography.fernet import Fernet; "
                "print(Fernet.generate_key().decode())\""
            ) from exc
    return _fernet


def encrypt(plaintext: str) -> str:
    """Encrypt a string and return a URL-safe base64 token."""
    if not plaintext:
        raise ValueError("Cannot encrypt empty string")
    return _get_fernet().encrypt(plaintext.encode("utf-8")).decode("utf-8")


def decrypt(ciphertext: str) -> str:
    """Decrypt a Fernet token back to a string."""
    if not ciphertext:
        raise ValueError("Cannot decrypt empty string")
    try:
        return _get_fernet().decrypt(ciphertext.encode("utf-8")).decode("utf-8")
    except InvalidToken as exc:
        raise ValueError(
            "Failed to decrypt token — key may have rotated or data is corrupt"
        ) from exc
