import os
import requests
from dotenv import load_dotenv
from enrichment.cache import get_cached, set_cached

# loading the vars from .env into the environmnet
load_dotenv()

def check_ip(ip):
    """Look up an IP address using the AbuseIPDB API."""
    cached = get_cached("abuseipdb", ip)
    if cached:
        return cached

    url="https://api.abuseipdb.com/api/v2/check"

    headers={
        "Key":os.getenv("ABUSEIPDB_API_KEY"),
        "Accept":"application/json"
    }

    params={
        "ipAddress": ip,
        "maxAgeInDays": 90, # How far back to consider reports
    }

    try:
        response=requests.get(url,headers=headers,params=params,timeout=10)
        response.raise_for_status() # raises an error on a bad HTTP status
        data = response.json()["data"]
    except requests.RequestException as e:
        return {"source": "abuseipdb", "ip": ip, "error": str(e)}
    
    result = {
        "source": "abuseipdb",
        "ip": ip,
        "abuse_score": data.get("abuseConfidenceScore"),   # 0-100
        "total_reports": data.get("totalReports"),
        "country": data.get("countryCode"),
        "isp": data.get("isp"),
        "is_tor": data.get("isTor"),
    }

    set_cached("abuseipdb",ip,result)
    return result