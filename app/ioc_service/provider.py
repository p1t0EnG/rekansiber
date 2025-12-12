# app/ioc_service/provider.py
import re
import asyncio
from typing import Dict, Any
import httpx
from aiocache import cached, Cache
from ..config import settings

# Regex patterns
ipv4_re = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")
md5_re = re.compile(r"^[A-Fa-f0-9]{32}$")
sha1_re = re.compile(r"^[A-Fa-f0-9]{40}$")
sha256_re = re.compile(r"^[A-Fa-f0-9]{64}$")
domain_re = re.compile(
    r"^(?=.{1,253}$)(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}"
    r"[a-zA-Z0-9])?\.)+[A-Za-z]{2,}$"
)

HTTP_TIMEOUT = httpx.Timeout(10.0, connect=5.0)

def detect_ioc_type(ioc: str) -> str:
    s = ioc.strip()
    if ipv4_re.match(s):
        return "ip"
    if md5_re.match(s) or sha1_re.match(s) or sha256_re.match(s):
        return "hash"
    if domain_re.match(s):
        return "domain"
    if any(c.isalpha() for c in s) and "." in s:
        return "domain"
    return "unknown"

# cached http getter (shared)
@cached(ttl=settings.CACHE_TTL_SECONDS, cache=Cache.MEMORY)
async def _cached_get(url: str, headers: dict | None = None, params: dict | None = None) -> Any:
    async with httpx.AsyncClient(timeout=HTTP_TIMEOUT) as client:
        r = await client.get(url, headers=headers or {}, params=params or {})
        r.raise_for_status()
        # Try JSON, fallback to text
        try:
            return r.json()
        except Exception:
            return r.text

# Provider calls (safe wrappers)
async def call_virustotal(ioc: str, ioc_type: str) -> Dict[str, Any]:
    if not settings.VT_KEY:
        return {"error": "VT_KEY not configured"}
    headers = {"x-apikey": settings.VT_KEY}
    if ioc_type == "ip":
        url = f"https://www.virustotal.com/api/v3/ip_addresses/{ioc}"
    elif ioc_type == "domain":
        url = f"https://www.virustotal.com/api/v3/domains/{ioc}"
    elif ioc_type == "hash":
        url = f"https://www.virustotal.com/api/v3/files/{ioc}"
    else:
        return {"error": "unsupported type"}
    try:
        data = await _cached_get(url, headers=headers)
        return {"ok": True, "data": data}
    except httpx.HTTPError as e:
        return {"ok": False, "error": str(e)}

async def call_abuseipdb(ip: str) -> Dict[str, Any]:
    if not settings.ABUSEIPDB_KEY:
        return {"error": "ABUSEIPDB_KEY not configured"}
    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {"Key": settings.ABUSEIPDB_KEY, "Accept": "application/json"}
    params = {"ipAddress": ip, "maxAgeInDays": 90}
    try:
        data = await _cached_get(url, headers=headers, params=params)
        return {"ok": True, "data": data}
    except httpx.HTTPError as e:
        return {"ok": False, "error": str(e)}

async def call_otx(ioc: str, ioc_type: str) -> Dict[str, Any]:
    if not settings.OTX_KEY:
        return {"error": "OTX_KEY not configured"}
    base = "https://otx.alienvault.com/api/v1/indicators"
    headers = {"X-OTX-API-KEY": settings.OTX_KEY}
    try:
        if ioc_type == "ip":
            url = f"{base}/IPv4/{ioc}/general"
        elif ioc_type == "domain":
            url = f"{base}/domain/{ioc}/general"
        else:
            return {"error": "unsupported type for OTX"}
        data = await _cached_get(url, headers=headers)
        return {"ok": True, "data": data}
    except httpx.HTTPError as e:
        return {"ok": False, "error": str(e)}

async def call_mxtoolbox(ioc: str, ioc_type: str) -> Dict[str, Any]:
    if not settings.MXTOOLBOX_KEY:
        return {"error": "MXTOOLBOX_KEY not configured"}
    # placeholder: adjust endpoint based on MXToolbox API you have access to
    url = f"https://api.mxtoolbox.com/api/v1/lookup/{ioc_type}/{ioc}"
    headers = {"Authorization": f"Bearer {settings.MXTOOLBOX_KEY}"}
    try:
        data = await _cached_get(url, headers=headers)
        return {"ok": True, "data": data}
    except httpx.HTTPError as e:
        return {"ok": False, "error": str(e)}

# Aggregator function
async def aggregate_ioc(ioc: str) -> Dict[str, Any]:
    ioc_type = detect_ioc_type(ioc)
    if ioc_type == "unknown":
        raise ValueError("Unable to detect IOC type (ip/domain/hash)")

    tasks = []
    # VirusTotal for any type
    tasks.append(call_virustotal(ioc, ioc_type))
    # AbuseIPDB only for IPs
    if ioc_type == "ip":
        tasks.append(call_abuseipdb(ioc))
    # OTX supports ip & domain
    if ioc_type in ("ip", "domain"):
        tasks.append(call_otx(ioc, ioc_type))
    # MXToolbox optional
    tasks.append(call_mxtoolbox(ioc, ioc_type))

    results = await asyncio.gather(*tasks, return_exceptions=True)

    # Map results to provider names in same order as tasks
    provider_names = ["virustotal"]
    if ioc_type == "ip":
        provider_names.append("abuseipdb")
    if ioc_type in ("ip", "domain"):
        provider_names.append("otx")
    provider_names.append("mxtoolbox")

    aggregated = {}
    for name, res in zip(provider_names, results):
        if isinstance(res, Exception):
            aggregated[name] = {"ok": False, "error": str(res)}
        else:
            aggregated[name] = res

    return {"ioc": ioc, "type": ioc_type, "results": aggregated}
