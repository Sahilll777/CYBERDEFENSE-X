from fastapi.testclient import TestClient

from app.main import app


client = TestClient(app)


def test_health_check():
    response = client.get("/health")

    assert response.status_code == 200

    assert response.json() == {
        "status": "healthy",
        "service": "CYBERDEFENSE-X",
        "environment": "development",
        "version": "0.1.0",
    }


def test_database_health_check():
    response = client.get("/health/database")

    assert response.status_code == 200

    assert response.json() == {
        "status": "healthy",
        "database": "postgresql",
    }