# app/config.py
import os
from pydantic import BaseSettings

class Settings(BaseSettings):
    # API keys
    ABUSEIPDB_KEY: str | None = None
    VT_KEY: str | None = None
    OTX_KEY: str | None = None
    MXTOOLBOX_KEY: str | None = None

    # Misc
    CACHE_TTL_SECONDS: int = 60 * 30  # 30 minutes
    ALLOW_ORIGINS: list[str] = ["*"]  # change in production

    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"

settings = Settings()
