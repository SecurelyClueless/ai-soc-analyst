import os
import json
import requests

CACHE_PATH = "cache/mitre_techniques.json"

ATTACK_URL = (
    "https://raw.githubusercontent.com/mitre/cti/master/"
    "enterprise-attack/enterprise-attack.json"
)

def _download_techniques():
    """"Download the ATT&CK dataset and extract {id: name} for techniques."""
    try:
        response = requests.get(ATTACK_URL, timeout=60)
        response.raise_for_status()
        data = response.json()
    except requests.RequestException as e:
        print(f"Error downloading ATT&CK data: {e}")
        return {}

    techniques = {}
    for obj in data.get("objects",[]):
        if obj.get("type")!= "attack-pattern":
            continue
        if obj.get("x_mitre_deprecated") or obj.get("revoked"):
            continue

        for ref in obj.get("external_references",[]):
            if ref.get("source_name") == "mitre-attack":
                tech_id = ref.get("external_id")
                if tech_id:
                    techniques[tech_id] = obj.get("name","")
    return techniques

def load_techniques():
    """Return {id: name} of all valid techniques, using a local cache."""

    if os.path.exists(CACHE_PATH):
        with open(CACHE_PATH, 'r') as f:
            return json.load(f)
    
    techniques = _download_techniques()
    if techniques:
        os.makedirs("cache", exist_ok=True)
        with open(CACHE_PATH,"w") as f:
            json.dump(techniques,f,indent=2)
    return techniques

def validate_mitre(mitre_list):
    """Check each proposed technique against the real ATT&CK catalogue.
    Adds a 'valid' flag and the official name to each entry.
    """
    valid_techniques = load_techniques()
    validated = []

    for item in mitre_list:
        tech_id = item.get("id","")
        is_valid = tech_id in valid_techniques
        validated.append({
            **item,
            "valid": is_valid,
            "official_name": valid_techniques.get(tech_id, None),
        })

    return validated