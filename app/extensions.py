# app/extensions.py
from aiocache import caches, Cache
from .config import settings

def init_extensions():
    # Default in-memory cache (for dev). Switch to redis in prod by changing config.
    caches.set_config({
        "default": {
            "cache": "aiocache.SimpleMemoryCache",
        }
    })

def get_cache():
    return caches.get("default")
