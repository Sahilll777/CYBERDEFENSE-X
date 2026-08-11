from datetime import datetime, timedelta, timezone

import jwt

from app.core.config import get_settings


def create_access_token(subject: str) -> str:
    """Create a signed JWT access token for the supplied subject."""

    settings = get_settings()

    now = datetime.now(timezone.utc)

    expires_at = now + timedelta(
        minutes=settings.jwt_access_token_expire_minutes
    )

    payload = {
        "sub": subject,
        "iat": now,
        "exp": expires_at,
        "type": "access",
    }

    return jwt.encode(
        payload,
        settings.jwt_secret_key,
        algorithm=settings.jwt_algorithm,
    )


def decode_access_token(token: str) -> dict:
    """Decode and validate a JWT access token."""

    settings = get_settings()

    return jwt.decode(
        token,
        settings.jwt_secret_key,
        algorithms=[settings.jwt_algorithm],
    )