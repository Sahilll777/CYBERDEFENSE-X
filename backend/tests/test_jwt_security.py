from datetime import datetime, timezone

import jwt

from app.core.config import get_settings
from app.security.jwt import create_access_token, decode_access_token


def test_create_access_token_contains_expected_claims():
    user_id = "12345"

    token = create_access_token(user_id)

    assert isinstance(token, str)
    assert len(token) > 20

    payload = decode_access_token(token)

    assert payload["sub"] == user_id
    assert payload["type"] == "access"
    assert "iat" in payload
    assert "exp" in payload


def test_access_token_has_future_expiration():
    token = create_access_token("12345")

    payload = decode_access_token(token)

    expiration = datetime.fromtimestamp(
        payload["exp"],
        tz=timezone.utc,
    )

    assert expiration > datetime.now(timezone.utc)


def test_invalid_token_is_rejected():
    settings = get_settings()

    invalid_token = jwt.encode(
        {
            "sub": "12345",
            "type": "access",
        },
        "this-is-an-intentionally-wrong-secret-key-for-tests",
        algorithm=settings.jwt_algorithm,
    )

    try:
        decode_access_token(invalid_token)
        assert False, "Invalid token should have been rejected."

    except jwt.InvalidTokenError:
        assert True