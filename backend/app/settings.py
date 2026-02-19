"""Configuration management — load from environment / .env."""

from pydantic import ConfigDict, Field
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    """Application settings loaded from .env and environment variables."""

    model_config = ConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    app_name: str = Field(default="Phishing Detection API", validation_alias="APP_NAME")
    debug: bool = Field(default=False, validation_alias="DEBUG")

    # Phish URL DB (OpenPhish feed). Path relative to cwd or absolute.
    phish_db_path: str = Field(default="data/phish_urls.db", validation_alias="PHISH_DB_PATH")


settings = Settings()
