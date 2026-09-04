"""Application configuration loaded from environment variables.

Usage:
    from shared.config import settings

    print(settings.github_token.get_secret_value())
"""

from __future__ import annotations

from pydantic import SecretStr, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """All configuration comes from environment variables (or .env file)."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # ── OpenAI ────────────────────────────────────────────────────────────────
    openai_api_key: SecretStr
    openai_model: str = "gpt-4o"

    # ── GitHub ────────────────────────────────────────────────────────────────
    github_token: SecretStr
    github_repo_owner: str
    github_repo_name: str
    github_webhook_secret: SecretStr
    # Only process issues with this label; empty string means process all
    github_issue_label: str = ""

    # ── Redis ─────────────────────────────────────────────────────────────────
    redis_url: str = "redis://localhost:6379/0"

    # ── Pipeline ──────────────────────────────────────────────────────────────
    # Risk score ≥ threshold → open PR as DRAFT (requires human review)
    risk_score_draft_threshold: int = 70
    # Maximum number of files the codegen agent will modify in one run
    max_files_per_issue: int = 10
    # Per-agent step timeout in seconds
    agent_timeout_seconds: int = 120

    # ── Logging ───────────────────────────────────────────────────────────────
    log_level: str = "INFO"

    # ── Optional: Semgrep ─────────────────────────────────────────────────────
    semgrep_app_token: str = ""

    @field_validator("log_level")
    @classmethod
    def _validate_log_level(cls, v: str) -> str:
        allowed = {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}
        upper = v.upper()
        if upper not in allowed:
            raise ValueError(f"log_level must be one of {allowed}, got {v!r}")
        return upper

    @property
    def github_repo_full_name(self) -> str:
        return f"{self.github_repo_owner}/{self.github_repo_name}"


# Module-level singleton — import this everywhere
settings = Settings()  # type: ignore[call-arg]
