import httpx
import asyncio

# In-memory cache for geolocation results
_geo_cache = {}

async def geolocate_ip(ip: str) -> dict:
    """
    Get geolocation data for an IP address using ip-api.com (free, no key).
    Returns a dict with lat, lon, city, country, isp.
    """
    # Check cache first
    if ip in _geo_cache:
        return _geo_cache[ip]

    # Skip private headers/reserved IPs if needed, but the caller usually filters these
    # The API will just return fail/reserved for them anyway.

    url = f"http://ip-api.com/json/{ip}"
    
    try:
        async with httpx.AsyncClient(timeout=5) as client:
            resp = await client.get(url)
            
        if resp.status_code == 200:
            data = resp.json()
            if data.get("status") == "success":
                result = {
                    "ip": ip,
                    "lat": data.get("lat"),
                    "lon": data.get("lon"),
                    "city": data.get("city", ""),
                    "country": data.get("country", ""),
                    "countryCode": data.get("countryCode", ""),
                    "isp": data.get("isp", ""),
                    "org": data.get("org", ""),
                    "has_geo": True
                }
                _geo_cache[ip] = result
                return result
    except Exception as e:
        print(f"[geolocation] Error geolocating {ip}: {e}")

    # Fallback/failure
    return {"ip": ip, "has_geo": False}
