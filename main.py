import json
import glob
import sys
from enrichment.enrich import enrich_alert
from triage.triage import triage_alert
from report.report import generate_report, save_report
from siem.query import fetch_encoded_powershell
from siem.parser import parse_event



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
    print("Fetching alerts from ELK...\n")
    docs = fetch_encoded_powershell()
    print(f"Found {len(docs)} events\n")

    for doc in docs:
        alert = parse_event(doc, detection="encoded_powershell")
        show_alert(alert)

        print("Enriching...")
        enriched = enrich_alert(alert)

        print("Running AI triage...")
        triage = triage_alert(enriched)

        report_text = generate_report(enriched, triage)
        out_path = save_report(report_text, alert["alert_id"])
        print(f"Report saved: {out_path}\n")

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