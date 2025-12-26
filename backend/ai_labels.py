import os
import logging

from openai import OpenAI

from db import get_db_connection

logger = logging.getLogger(__name__)

# Core LL labels we always want available
DEFAULT_LL_LABELS = [
    "@LL-Blackhole",
    "@LL-Finance",
    "@LL-Purchases",
    "@LL-Security",
    "@LL-Soliciting",
    "@LL-News",
    "@LL-Travel",
    "@LL-Threat",
]

BASE_AI_LABELS = DEFAULT_LL_LABELS[:]  # copy

OPENAI_API_KEY = os.environ.get("OPENAI_API_KEY", "")
openai_client = OpenAI(api_key=OPENAI_API_KEY) if OPENAI_API_KEY else None


def get_dynamic_ll_labels_from_db():
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute(
            "SELECT DISTINCT label_name FROM rules WHERE label_name LIKE '@LL-%';"
        )
        rows = cur.fetchall()
        conn.close()
        return [r["label_name"] for r in rows if r["label_name"]]
    except Exception:
        logger.exception("Failed to load dynamic LL labels from rules")
        return []


def get_allowed_ai_labels():
    labels = set(BASE_AI_LABELS)
    dynamic = get_dynamic_ll_labels_from_db()
    for lbl in dynamic:
        labels.add(lbl)

    labels_list = sorted(labels)
    labels_list.append("None")
    return labels_list


def ai_suggest_label(sender, subject, body):
    """
    Use OpenAI to suggest a label from the allowed list.
    """
    if not openai_client or not OPENAI_API_KEY:
        return None, 0.0

    allowed_labels = get_allowed_ai_labels()
    label_map = {lbl.lower(): lbl for lbl in allowed_labels}
    label_list = ", ".join(allowed_labels)

    system_prompt = (
        "You are an email classifier for a personal inbox. "
        "You must choose exactly one label from the allowed list, "
        "or 'None' if the email does not clearly fit any category."
    )

    user_prompt = f"""
Allowed labels:
{label_list}

Sender: {sender}
Subject: {subject}
Body (truncated):
{body[:1200]}

Respond with only the label text (exactly as in the list) or 'None'.
"""

    try:
        resp = openai_client.chat.completions.create(
            model="gpt-4o",
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
            max_tokens=20,
            temperature=0,
        )
        raw = (resp.choices[0].message.content or "").strip()
        norm = label_map.get(raw.lower())
        if not norm or norm == "None":
            return None, 0.0

        confidence = 0.75  # placeholder confidence
        return norm, confidence
    except Exception:
        logger.exception("Error from OpenAI while suggesting label")
        return None, 0.0
