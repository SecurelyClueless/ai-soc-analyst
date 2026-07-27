import os
import json

WATERMARK_PATH = "cache/watermark.json"


def get_watermark(detection):
    """Return the last-processed timestamp for a detection, or None."""
    if not os.path.exists(WATERMARK_PATH):
        return None
    try:
        with open(WATERMARK_PATH, "r") as f:
            data = json.load(f)
        return data.get(detection)
    except (json.JSONDecodeError, OSError):
        return None


def set_watermark(detection, timestamp):
    """Save the last-processed timestamp for a detection."""
    # Load existing watermarks so we don't clobber other detections'.
    data = {}
    if os.path.exists(WATERMARK_PATH):
        try:
            with open(WATERMARK_PATH, "r") as f:
                data = json.load(f)
        except (json.JSONDecodeError, OSError):
            data = {}

    data[detection] = timestamp

    os.makedirs("cache", exist_ok=True)
    with open(WATERMARK_PATH, "w") as f:
        json.dump(data, f, indent=2)