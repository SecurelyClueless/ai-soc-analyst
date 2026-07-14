import json
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
    alert = load_alert("alerts/sample_alert.json")
    #show_alert(alert)

    print("\nEnriching alert...")
    enriched = enrich_alert(alert)

    print("\n Running AI triage...")
    triage = triage_alert(enriched)
    # print(json.dumps(triage,indent=2))
    
    print("\nGenerating incident report...")
    report_text = generate_report(enriched, triage)
    path = save_report(report_text, alert["alert_id"])
    print(f"Report saved to: {path}")