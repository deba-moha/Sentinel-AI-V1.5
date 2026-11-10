"""
Sentinel AI V1.5 - Core Configuration
Manages environment variables, server parameters, and centralized detection thresholds.
"""
from typing import List, Union
from pydantic_settings import BaseSettings, SettingsConfigDict
from pydantic import field_validator


class Settings(BaseSettings):
    # Server & Service Identification
    PROJECT_NAME: str = "Sentinel AI"
    VERSION: str = "1.5.0"
    ENVIRONMENT: str = "development"
    LOG_LEVEL: str = "INFO"
    HOST: str = "127.0.0.1"
    PORT: int = 8000

    # Database & Network
    DATABASE_URL: str = "sqlite:///./sentinel.db"
    CORS_ORIGINS: Union[str, List[str]] = "http://localhost:5173,http://127.0.0.1:5173"

    # Centralized Detection Engine Thresholds (Configurable via .env)
    BRUTE_FORCE_THRESHOLD: int = 5
    BRUTE_FORCE_WINDOW_SECONDS: int = 60

    PORT_SCAN_THRESHOLD: int = 5
    PORT_SCAN_WINDOW_SECONDS: int = 30

    DDOS_MIN_EVENTS: int = 20
    DDOS_MIN_SOURCES: int = 3
    DDOS_WINDOW_SECONDS: int = 30

    ANOMALOUS_SPIKE_THRESHOLD: int = 20
    ANOMALOUS_SPIKE_WINDOW_SECONDS: int = 60

    # Machine Learning Anomaly Detection Settings (Phase 4)
    ENABLE_ML_DETECTION: bool = True
    ML_ANOMALY_THRESHOLD: float = -0.0200
    ML_WINDOW_SECONDS: int = 60
    ML_MIN_EVENTS: int = 5

    @field_validator("CORS_ORIGINS", mode="before")
    def parse_cors_origins(cls, v: Union[str, List[str]]) -> List[str]:
        if isinstance(v, str):
            return [origin.strip() for origin in v.split(",") if origin.strip()]
        return v

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore"
    )


settings = Settings()
