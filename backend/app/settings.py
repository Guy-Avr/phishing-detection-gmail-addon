"""Configuration management — load from environment / .env."""

from typing import Literal

from pydantic import ConfigDict, Field
from pydantic_settings import BaseSettings

LLMProviderChoice = Literal["ollama", "gemini"]


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

    # LLM (only when verdict is Suspicious): choose single provider via LLM_PROVIDER
    llm_provider: LLMProviderChoice = Field(
        default="ollama",
        validation_alias="LLM_PROVIDER",
    )
    ollama_url: str = Field(default="http://localhost:11434", validation_alias="OLLAMA_URL")
    ollama_model: str = Field(default="llama2", validation_alias="OLLAMA_MODEL")
    gemini_api_key: str = Field(default="", validation_alias="GEMINI_API_KEY")
    gemini_model: str = Field(default="gemini-1.5-flash", validation_alias="GEMINI_MODEL")
    llm_timeout_sec: float = Field(default=30.0, validation_alias="LLM_TIMEOUT_SEC")


settings = Settings()
