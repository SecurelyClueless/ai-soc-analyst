import json
import glob
import sys
from enrichment.enrich import enrich_alert
from triage.triage import triage_alert
from report.report import generate_report, save_report
from siem.query import fetch_encoded_powershell
from siem.parser import parse_event
from siem.watermark import get_watermark, set_watermark




def load_alert(path):
    with open(path, 'r') as f:
        return json.load(f)
    
def show_alert(alert):
    print("=" * 50)
    print(f"Alert:    {alert.get('alert_name')}")
    sev = alert.get('severity') or 'unknown'
    print(f"Severity: {sev.upper()}")
    print(f"Host:     {alert.get('host')} (user: {alert.get('user')})")
    print(f"Source:   {alert.get('src_ip')}  ->  {alert.get('dest_ip')}")
    print(f"Process:  {alert.get('process')}")
    print(f"Hash:     {alert.get('file_hash')}")
    print("=" * 50)

def run_from_elk():
    detection = "encoded_powershell"

    last_seen = get_watermark(detection)
    print(f"Fetching alerts from ELK (since: {last_seen or 'beginning'})...\n")

    docs = fetch_encoded_powershell(after=last_seen)
    print(f"Found {len(docs)} new events\n")

    newest_timestamp = last_seen

    for doc in docs:
        alert = parse_event(doc, detection=detection)
        show_alert(alert)

        print("Enriching...")
        enriched = enrich_alert(alert)

        print("Running AI triage...")
        triage = triage_alert(enriched)

        report_text = generate_report(enriched, triage)
        out_path = save_report(report_text, alert["alert_id"])
        print(f"Report saved: {out_path}\n")

        # Track the newest timestamp we've processed.
        ts = alert["timestamp"]
        if newest_timestamp is None or ts > newest_timestamp:
            newest_timestamp = ts

    # Save the watermark only after successfully processing everything.
    if newest_timestamp and newest_timestamp != last_seen:
        set_watermark(detection, newest_timestamp)
        print(f"Watermark updated to: {newest_timestamp}")

def run_from_files():
    alert_files = glob.glob("alerts/*.json")
    print(f"Found {len(alert_files)} alerts to process.\n")

    for path in alert_files:
        alert = load_alert(path)
        show_alert(alert)

        print("Enriching...")
        enriched = enrich_alert(alert)

        print("Running AI triage...")
        triage = triage_alert(enriched)

        report_text = generate_report(enriched, triage)
        out_path = save_report(report_text, alert["alert_id"])
        print(f"Report saved: {out_path}\n")

if __name__ == "__main__":
    source = sys.argv[1] if len(sys.argv) > 1 else "file"

    if source == "elk":
        run_from_elk()
    else:
        run_from_files()