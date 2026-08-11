from fastapi import FastAPI

from app.core.config import get_settings


settings = get_settings()


app = FastAPI(
    title=settings.app_name,
    description="Enterprise Security Operations & Threat Detection Platform",
    version="0.1.0",
)


@app.get("/health")
def health_check() -> dict[str, str]:
    return {
        "status": "healthy",
        "service": settings.app_name,
        "environment": settings.app_env,
        "version": "0.1.0",
    }