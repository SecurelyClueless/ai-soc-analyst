import json
from enrichment.abuseipdb import check_ip

def load_alert(path):
    with open(path, 'r') as f:
        return json.load(f)
    
def show_alert(alert):
    print("=" * 50)
    print(f"Alert:      {alert['alert_name']}")
    print(f"Severity:   {alert['severity'].upper()}")
    print(f"Host:       {alert['host']}    (user:  {alert['user']})")
    print(f"Source:     {alert['src_ip']} -> {alert['dest_ip']}")
    print(f"Process:  {alert['process']}")
    print(f"Hash:     {alert['file_hash']}")
    print("=" * 50)

if __name__ == "__main__":
    alert = load_alert("alerts/sample_alert.json")
    #show_alert(alert)

    print("\n Enrichment destination IP ")
    result=check_ip(alert["dest_ip"])
    print(result)