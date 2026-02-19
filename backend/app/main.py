"""FastAPI application entry point."""

from fastapi import FastAPI

from app.settings import settings
from app.api.endpoints import health  # example router

app = FastAPI(
    title=settings.app_name,
    debug=settings.debug,
)

# Include routers
app.include_router(health.router, prefix="/health", tags=["health"])


@app.get("/")
def root():
    return {"message": "Welcome to the API"}
