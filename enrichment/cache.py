import os 
import json
import hashlib

CACHE_DIR = "cache/enrichment"

def _cache_path(source,key):
    """Build a safe filename for this source + indicator"""
    safe_key = hashlib.sha256(key.encode()).hexdigest()[:16]
    return os.path.join(CACHE_DIR, f"{source}_{safe_key}.json")

def get_cached(source,key):
    path = _cache_path(source,key)
    if not os.path.exists(path):
        return None
    try:
        with open(path, "r") as f:
            return json.load(f)
    except (json.JSONDecodeError, OSError):
        return None
    
def set_cached(source,key,value):
    if not value or "error" in value:
        return
    
    os.makedirs(CACHE_DIR, exist_ok=True)
    path = _cache_path(source,key)
    with open(path,"w") as f:
        json.dump(value,f,indent=2)