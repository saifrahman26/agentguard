"""
AgentGuard Configuration System

Uses pydantic-settings to load from environment variables and .env file.
All configuration is typed and validated at startup.
The system must remain functional even if optional fields (LLM API keys) are absent.
"""
from pydantic_settings import BaseSettings, SettingsConfigDict
from pydantic import Field
from enum import Enum
from pathlib import Path


class LogLevel(str, Enum):
    DEBUG = "DEBUG"
    INFO = "INFO"
    WARNING = "WARNING"
    ERROR = "ERROR"


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # Application
    app_name: str = "AgentGuard"
    app_version: str = "0.1.0"
    debug: bool = False

    # Database
    database_url: str = "sqlite:///./agentguard.db"

    # Logging
    log_level: LogLevel = LogLevel.INFO
    log_file: str = "agentguard.log"

    # Security thresholds (0-100)
    max_risk_score: int = 100
    review_threshold: int = 60   # score >= 60 -> REVIEW
    block_threshold: int = 80    # score >= 80 -> BLOCK

    # Network policy default
    default_network_policy: str = "deny"

    # Optional LLM (system works WITHOUT these)
    llm_provider: str | None = None
    llm_api_key: str | None = None
    llm_model: str | None = None

    # Policy and audit paths
    policy_config_path: str = "./policies/default_policy.json"
    audit_log_path: str = "./audit_logs/audit.jsonl"


_settings_instance: Settings | None = None


def get_settings() -> Settings:
    """Return the singleton Settings instance."""
    global _settings_instance
    if _settings_instance is None:
        _settings_instance = Settings()
    return _settings_instance
