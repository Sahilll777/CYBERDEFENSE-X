from fastapi import FastAPI


app = FastAPI(
    title="CYBERDEFENSE-X",
    description="Enterprise Security Operations & Threat Detection Platform",
    version="0.1.0",
)


@app.get("/health")
def health_check():
    return {
        "status": "healthy",
        "service": "CYBERDEFENSE-X",
        "version": "0.1.0",
    }