import json
import glob
from enrichment.enrich import enrich_alert
from triage.triage import triage_alert
from report.report import generate_report, save_report


def load_alert(path):
    with open(path, 'r') as f:
        return json.load(f)
    
def show_alert(alert):
    print("=" * 50)
    print(f"Alert:    {alert['alert_name']}")
    print(f"Severity: {alert['severity'].upper()}")
    print(f"Host:     {alert['host']} (user: {alert['user']})")
    print(f"Source:   {alert['src_ip']}  ->  {alert['dest_ip']}")
    print(f"Process:  {alert['process']}")
    print(f"Hash:     {alert['file_hash']}")
    print("=" * 50)

if __name__ == "__main__":
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