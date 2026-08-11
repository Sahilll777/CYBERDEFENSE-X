from app.security.password import hash_password, verify_password


def test_password_hash_is_not_plaintext():
    password = "TestPassword123!"

    hashed_password = hash_password(password)

    assert hashed_password != password


def test_password_hash_can_be_verified():
    password = "TestPassword123!"

    hashed_password = hash_password(password)

    assert verify_password(password, hashed_password) is True


def test_wrong_password_is_rejected():
    password = "TestPassword123!"

    hashed_password = hash_password(password)

    assert verify_password("WrongPassword123!", hashed_password) is False