# app/config.py
import os, json
from pydantic import BaseSettings

class Settings(BaseSettings):
    # fallback if someone stores individual keys (optional)
    VT_KEY: str | None = None
    ABUSEIPDB_KEY: str | None = None
    OTX_KEY: str | None = None
    MXTOOLBOX_KEY: str | None = None

    # combined secret
    API_KEYS: str | None = None

    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"

settings = Settings()

# parse API_KEYS JSON if present and populate missing values
if settings.API_KEYS:
    try:
        parsed = json.loads(settings.API_KEYS)
        # only set those not already present
        if not settings.VT_KEY and "VT_KEY" in parsed:
            settings.VT_KEY = parsed["VT_KEY"]
        if not settings.ABUSEIPDB_KEY and "ABUSEIPDB_KEY" in parsed:
            settings.ABUSEIPDB_KEY = parsed["ABUSEIPDB_KEY"]
        if not settings.OTX_KEY and "OTX_KEY" in parsed:
            settings.OTX_KEY = parsed["OTX_KEY"]
        if not settings.MXTOOLBOX_KEY and "MXTOOLBOX_KEY" in parsed:
            settings.MXTOOLBOX_KEY = parsed["MXTOOLBOX_KEY"]
    except Exception:
        # log warning in real app
        pass
