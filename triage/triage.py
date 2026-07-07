import os
import json
from anthropic import Anthropic
from dotenv import load_dotenv

load_dotenv()

client = Anthropic(api_key=os.getenv("ANTHROPIC_API_KEY"))

SYSTEM_PROMPT = """You are a SOC analyst assistant. You triage security alerts.

Rules you must follow:
- Base your analysis ONLY on the alert and enrichment data provided.
- Do NOT invent evidence, IPs, hashes, or facts not present in the data.
- If data is missing or inconclusive, say "unknown" rather than guessing.
- Map findings to real MITRE ATT&CK techniques only.

Respond with ONLY a valid JSON object, no preamble or markdown, in this exact shape:
{
  "severity": "high | medium | low",
  "severity_reason": "one sentence explaining the severity",
  "summary": "2-3 sentence plain-language summary of what happened",
  "mitre": [{"tactic": "...", "technique": "...", "id": "T1234"}],
  "recommended_actions": ["action 1", "action 2"],
  "triage_decision": "true_positive | false_positive | needs_investigation",
  "confidence": "high | medium | low"
}"""

def triage_alert(enriched_alert):
    """"Send an enriched alet ot the LLM and get a structured triage."""

    user_content = (
        "Triage this security alert. \n\n"
        + json.dumps(enriched_alert, indent=2)
    )

    response = client.messages.create(
        model="claude-haiku-4-5",
        max_tokens=1000,
        system=SYSTEM_PROMPT,
        messages=[{"role": "user", "content": user_content}]
    )

    raw_text = response.content[0].text 
    cleaned = raw_text.strip().removeprefix("```json").removeprefix("```").removesuffix("```").strip()

    try:
        return json.loads(cleaned)
    except json.JSONDecodeError as e:
        return {
            "error": "Failed to parse LLM response as JSON",
            "raw_response": raw_text,
            "cleaned_response": cleaned,
            "exception": str(e)
        }