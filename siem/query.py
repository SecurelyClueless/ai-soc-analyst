import os
from elasticsearch import Elasticsearch
from dotenv import load_dotenv, find_dotenv

load_dotenv(find_dotenv())


def get_client():
    """Build an authenticated Elasticsearch client."""
    return Elasticsearch(
        os.getenv("ELASTIC_HOST"),
        basic_auth=(os.getenv("ELASTIC_USER"), os.getenv("ELASTIC_PASSWORD")),
        ca_certs=os.getenv("ELASTIC_CA_CERT"),
    )


def fetch_encoded_powershell(size=10):
    """Find Sysmon process-creation events using encoded PowerShell."""
    es = get_client()

    query = {
        "bool": {
            "must": [
                {"term": {"winlog.event_id": "1"}},
                {"match": {"process.command_line.text": "EncodedCommand"}},
            ]
        }
    }

    response = es.search(
        index="winlogbeat-*",
        query=query,
        size=size,
        sort=[{"@timestamp": {"order": "desc"}}],
    )

    # Each hit's actual document lives under "_source"
    return [
    {**hit["_source"], "_es_id": hit["_id"]}
    for hit in response["hits"]["hits"]]


if __name__ == "__main__":
    docs = fetch_encoded_powershell()
    print(f"Found {len(docs)} matching events\n")
    for doc in docs:
        print(doc.get("@timestamp"), "|", doc.get("process", {}).get("command_line", "")[:80])