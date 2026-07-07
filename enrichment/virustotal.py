import os 
import requests
from dotenv import load_dotenv

load_dotenv()

def check_hash(file_hash):
    """Look up a file on VirusTotal"""
    url=f"https://www.virustotal.com/api/v3/files/{file_hash}"

    headers={
        "x-apikey": os.getenv("VIRUSTOTAL_API_KEY"),
    }

    try:
        response = requests.get(url,headers=headers,timeout=10)
        response.raise_for_status()
        data=response.json()["data"]["attributes"] 
    except requests.RequestException as e:
        return {"source":"virustotal", "hash": file_hash, "error": str(e)}
    
    stats = data.get("last_analysis_stats",{})

    return {
        "source": "virustotal",
        "hash": file_hash,
        "malicious": stats.get("malicious"),      # how many engines said malicious
        "suspicious": stats.get("suspicious"),
        "harmless": stats.get("harmless"),
        "undetected": stats.get("undetected"),
        "reputation": data.get("reputation"),
        "meaningful_name": data.get("meaningful_name"),  # file's known name, if any
    }