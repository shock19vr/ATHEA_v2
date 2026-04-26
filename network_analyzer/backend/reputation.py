"""
AbuseIPDB reputation service.

Provides async IP reputation checks with:
- In-memory cache (avoids repeated lookups for the same IP)
- Private/reserved IP filtering (skips local addresses)
- Rate-limit awareness (1,000 checks/day on free tier)
"""

import os
import ipaddress
import httpx
from .geolocation import geolocate_ip

# Ensure .env is loaded (fallback in case main.py didn't load it)
from dotenv import load_dotenv, find_dotenv
_this_dir = os.path.dirname(os.path.abspath(__file__))
load_dotenv(find_dotenv(), override=True)
load_dotenv(os.path.join(_this_dir, '../../.env'), override=True)         # project root
load_dotenv(os.path.join(_this_dir, '.env'), override=True)               # backend dir

ABUSEIPDB_URL = "https://api.abuseipdb.com/api/v2/check"

# In-memory cache: ip -> result dict
_cache: dict[str, dict] = {}


def _is_private(ip: str) -> bool:
    """Return True if the IP is private, loopback, link-local, or reserved."""
    try:
        addr = ipaddress.ip_address(ip)
        return addr.is_private or addr.is_loopback or addr.is_link_local or addr.is_reserved
    except ValueError:
        return True  # malformed → treat as private / skip


def _classify(score: int) -> str:
    """Classify IP based on abuse score."""
    if score == 0:
        return "Safe"
    if score < 25:
        return "Suspicious"
    return "Unsafe"


async def check_ip(ip: str) -> dict:
    """
    Look up an IP against AbuseIPDB.

    Returns a dict with keys:
        ip, abuseConfidenceScore, classification, country, isp, domain,
        totalReports, isPublic, skipped, cached
    """
    # Skip private IPs
    if _is_private(ip):
        return {"ip": ip, "skipped": True, "reason": "private/reserved IP"}

    # Return cached result if available
    if ip in _cache:
        return {**_cache[ip], "cached": True}

    api_key = os.environ.get("ABUSEIPDB_API_KEY", "")
    if not api_key or api_key == "your_api_key_here":
        print(f"[reputation] Skipping {ip} — ABUSEIPDB_API_KEY not set (current value: '{api_key[:8]}...')")
        return {"ip": ip, "skipped": True, "reason": "API key not configured"}

    try:
        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.get(
                ABUSEIPDB_URL,
                headers={"Key": api_key, "Accept": "application/json"},
                params={"ipAddress": ip, "maxAgeInDays": "90"},
            )

        if resp.status_code == 429:
            return {"ip": ip, "skipped": True, "reason": "rate limit exceeded"}

        if resp.status_code != 200:
            print(f"[reputation] API error for {ip}: HTTP {resp.status_code}")
            return {"ip": ip, "skipped": True, "reason": f"API error {resp.status_code}"}

        data = resp.json().get("data", {})
        score = data.get("abuseConfidenceScore", 0)

        # Get geolocation data interactively
        geo = await geolocate_ip(ip)

        result = {
            "ip": ip,
            "abuseConfidenceScore": score,
            "classification": _classify(score),
            "country": data.get("countryCode", "") or geo.get("countryCode", ""),
            "isp": data.get("isp", "") or geo.get("isp", ""),
            "domain": data.get("domain", ""),
            "totalReports": data.get("totalReports", 0),
            "isPublic": True,
            "skipped": False,
            # Geo fields
            "lat": geo.get("lat"),
            "lon": geo.get("lon"),
            "city": geo.get("city", ""),
            "has_geo": geo.get("has_geo", False),
        }

        print(f"[reputation] {ip} → score={score} ({result['classification']}), country={result['country']}, loc={result.get('city','')}")
        _cache[ip] = result
        return result

    except httpx.TimeoutException:
        return {"ip": ip, "skipped": True, "reason": "request timed out"}
    except Exception as e:
        return {"ip": ip, "skipped": True, "reason": str(e)}


def get_cache() -> dict[str, dict]:
    """Return the current cache (for diagnostics / bulk view)."""
    return dict(_cache)


def clear_cache():
    """Clear the in-memory cache."""
    _cache.clear()
