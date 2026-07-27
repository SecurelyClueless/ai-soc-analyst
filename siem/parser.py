import json
from pathlib import Path
from siem.detections import DETECTIONS

SAMPLE = Path(__file__).parent / "sample_event.json"


def _get(doc, path, default=None):
    """Safely walk a dotted path through nested dicts."""
    current = doc
    for key in path.split("."):
        if not isinstance(current, dict):
            return default
        current = current.get(key)
        if current is None:
            return default
    return current


def _lab_ip(doc, prefix="192.168.100."):
    """host.ip is an array — pick the lab-subnet address."""
    for ip in _get(doc, "host.ip", []) or []:
        if ip.startswith(prefix):
            return ip
    return None


def parse_event(doc, detection=None):
    """Convert one ECS document into the alert schema.

    `detection` is a key into DETECTIONS supplying the verdict fields
    (alert_name, severity, description) that aren't present in the raw event.
    """
    meta = DETECTIONS.get(detection, {})

    return {
        "alert_id": _get(doc, "_es_id"),
        "alert_name": meta.get("alert_name"),
        "severity": meta.get("severity"),
        "timestamp": _get(doc, "@timestamp"),
        "host": _get(doc, "host.hostname"),
        "user": _get(doc, "user.name"),
        "src_ip": _lab_ip(doc),
        "dest_ip": None,
        "process": _get(doc, "process.name"),
        "command_line": _get(doc, "process.command_line"),
        "file_hash": _get(doc, "process.hash.sha256"),
        "description": meta.get("description"),
    }


if __name__ == "__main__":
    with open(SAMPLE) as f:
        doc = json.load(f)
        doc = doc.get("_source", doc)
    print(json.dumps(parse_event(doc, detection="encoded_powershell"), indent=2))