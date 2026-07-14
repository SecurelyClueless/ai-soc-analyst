from enrichment.abuseipdb import check_ip
from enrichment.virustotal import check_hash

CONFIG = {
    "abuse_score_suspicious": 50,  # Threshold for considering an IP suspicious
    "vt_malicious_min": 1,  # Threshold for considering a file hash malicious
}

def build_risk_flags(ip_data,hash_data):
    """Turn raw enchrichment data into human-readable risk signals."""
    flags = []

    if ip_data.get("abuse_score") is not None:
        if ip_data["abuse_score"] >= CONFIG["abuse_score_suspicious"]:
            flags.append("suspicious_ip_reputation")
        if ip_data.get("is_tor"):
            flags.append("tor_exit_node")

    if hash_data.get("malicious") is not None:
        if hash_data["malicious"] >= CONFIG["vt_malicious_min"]:
            flags.append("known_malware")
    
    return flags


def enrich_alert(alert):
    """Run every enrichment source and merge into one structured record."""
    ip_data = {}
    hash_data = {}

    if alert.get("dest_ip"):
        ip_data = check_ip(alert["dest_ip"])
    if alert.get("file_hash"):
        hash_data = check_hash(alert["file_hash"])

    risk_flags = build_risk_flags(ip_data,hash_data)

    return {
        "alert":alert,
        "enrichment": {
            "ip": ip_data,
            "hash": hash_data,
        },
        "risk_flags": risk_flags
    }
    