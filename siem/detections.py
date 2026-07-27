# Each detection pairs a query with the metadata a hit implies.
# The query IS the detection — a match means this thing happened.

DETECTIONS = {
    "encoded_powershell": {
        "alert_name": "Encoded PowerShell Execution",
        "severity": "high",
        "description": "PowerShell executed with an encoded command, a technique commonly used to obscure malicious payloads from logging and inspection.",
    },
}