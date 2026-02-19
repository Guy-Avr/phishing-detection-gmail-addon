"""Configuration management - load from environment / .env."""

from pydantic import ConfigDict
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    """Application settings loaded from environment variables."""

    model_config = ConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    app_name: str = "Phishing Detection API"
    debug: bool = False

    # Database (example)
    database_url: str = "sqlite:///./app.db"


settings = Settings()
