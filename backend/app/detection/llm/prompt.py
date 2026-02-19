"""
Single, reusable prompt template for phishing risk analysis.

Role and output format are fixed; input is subject, sender, body.
Prompt is built here only; providers receive the final string.
"""

import json

# Role and output schema; input placeholders filled by analyzer.
_SYSTEM = (
    "You are a cybersecurity analyst. Analyze the following email and assess phishing risk. "
    "This analysis is an auxiliary signal only and must not override an existing classification. "
    "Respond with ONLY a single JSON object, no other text. "
    'Format: {"risk_score": <number between 0 and 1>, "reasons": [<up to 3 short strings>]}.'
)

_USER_TEMPLATE = """Subject: {subject}
Sender: {sender}
Body:
{body}"""


def build_phishing_prompt(subject: str, sender: str, body: str, max_body_chars: int = 4000) -> str:
    """
    Build the full prompt for the LLM.

    Truncates body to max_body_chars to avoid token overflow and cost.
    Subject and sender are short; only body is truncated.
    """
    body_trimmed = (body or "")[:max_body_chars]
    if len(body or "") > max_body_chars:
        body_trimmed += "\n[... truncated]"
    user_part = _USER_TEMPLATE.format(
        subject=subject or "(none)",
        sender=sender or "(none)",
        body=body_trimmed or "(empty)",
    )
    return f"{_SYSTEM}\n\n{user_part}"
