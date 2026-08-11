from sqlalchemy.orm import Session

from app.repositories.user_repository import UserRepository
from app.security.jwt import create_access_token
from app.security.password import hash_password, verify_password


class AuthenticationError(Exception):
    """Raised when authentication credentials are invalid."""


class InactiveUserError(Exception):
    """Raised when an inactive user attempts authentication."""


class AuthService:
    """Business logic for authentication and user registration."""

    def __init__(self, db: Session):
        self.user_repository = UserRepository(db)

    def register_user(
        self,
        *,
        username: str,
        email: str,
        password: str,
        full_name: str | None = None,
    ):
        existing_username = self.user_repository.get_by_username(username)

        if existing_username is not None:
            raise ValueError("Username already exists.")

        existing_email = self.user_repository.get_by_email(email)

        if existing_email is not None:
            raise ValueError("Email already exists.")

        password_hash = hash_password(password)

        return self.user_repository.create(
            username=username,
            email=email,
            password_hash=password_hash,
            full_name=full_name,
        )

    def authenticate_user(
        self,
        *,
        username: str,
        password: str,
    ):
        user = self.user_repository.get_by_username(username)

        if user is None:
            raise AuthenticationError("Invalid username or password.")

        if not verify_password(password, user.password_hash):
            raise AuthenticationError("Invalid username or password.")

        if not user.is_active:
            raise InactiveUserError("User account is inactive.")

        return user

    def login(
        self,
        *,
        username: str,
        password: str,
    ) -> str:
        user = self.authenticate_user(
            username=username,
            password=password,
        )

        return create_access_token(str(user.id))