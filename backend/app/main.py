from fastapi import FastAPI
from sqlalchemy import text
from app.api.rbac import router as rbac_router
from app.api.auth import router as auth_router
from app.core.config import get_settings
from app.core.database import engine
from app.api.security_events import router as security_events_router

settings = get_settings()


app = FastAPI(
    title=settings.app_name,
    description="Enterprise Security Operations & Threat Detection Platform",
    version="0.1.0",
)


app.include_router(auth_router)
app.include_router(rbac_router)
app.include_router(security_events_router)

@app.get("/health")
def health_check() -> dict[str, str]:
    return {
        "status": "healthy",
        "service": settings.app_name,
        "environment": settings.app_env,
        "version": "0.1.0",
    }


@app.get("/health/database")
def database_health_check() -> dict[str, str]:
    with engine.connect() as connection:
        connection.execute(text("SELECT 1"))

    return {
        "status": "healthy",
        "database": "postgresql",
    }