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


def fetch_encoded_powershell(after=None, size=100):
    """Find Sysmon Event 1 encoded-PowerShell events newer than `after`."""
    es = get_client()

    must = [
        {"term": {"winlog.event_id": "1"}},
        {"match": {"process.command_line.text": "EncodedCommand"}},
    ]

    # Only fetch events strictly newer than the watermark.
    if after:
        must.append({"range": {"@timestamp": {"gt": after}}})

    query = {"bool": {"must": must}}

    response = es.search(
        index="winlogbeat-*",
        query=query,
        size=size,
        sort=[{"@timestamp": {"order": "asc"}}],   # oldest first — see below
    )

    return [
        {**hit["_source"], "_es_id": hit["_id"]}
        for hit in response["hits"]["hits"]
    ]


if __name__ == "__main__":
    docs = fetch_encoded_powershell()
    print(f"Found {len(docs)} matching events\n")
    for doc in docs:
        print(doc.get("@timestamp"), "|", doc.get("process", {}).get("command_line", "")[:80])