from collections.abc import Generator

from sqlalchemy import create_engine
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker

from app.core.config import get_settings


settings = get_settings()


engine = create_engine(
    settings.database_url,
    pool_pre_ping=True,
)


SessionLocal = sessionmaker(
    bind=engine,
    autoflush=False,
    autocommit=False,
)


class Base(DeclarativeBase):
    """Base class for all CYBERDEFENSE-X SQLAlchemy models."""


def get_db() -> Generator[Session, None, None]:
    """Provide a database session for a FastAPI request."""
    db = SessionLocal()

    try:
        yield db
    finally:
        db.close()