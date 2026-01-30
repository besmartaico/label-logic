import os
import json
import logging
from typing import Dict, List, Tuple

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
        cur.execute("SELECT DISTINCT label_name FROM rules WHERE label_name LIKE '@LL-%';")
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
{(body or '')[:1200]}

Respond with only the label text (exactly as in the list) or 'None'.
"""

    try:
        resp = openai_client.chat.completions.create(
            model=os.environ.get("OPENAI_MODEL", "gpt-4o"),
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


def _strip_code_fences(text: str) -> str:
    """Remove ```json ... ``` wrappers if the model returns fenced output."""
    if not text:
        return ""
    t = text.strip()
    if t.startswith("```"):
        parts = t.split("\n")
        parts = parts[1:]  # drop ``` or ```json
        if parts and parts[-1].strip().startswith("```"):
            parts = parts[:-1]
        return "\n".join(parts).strip()
    return t


def ai_suggest_labels_bulk(
    items: List[Dict[str, str]],
    *,
    max_body_chars: int = 900,
    model: str | None = None,
) -> Dict[str, Tuple[str | None, float]]:
    """
    Classify many emails in a SINGLE OpenAI call.

    Args:
        items: list of dicts: {"id": <gmail_id>, "sender": str, "subject": str, "body": str}
        max_body_chars: body truncation for prompt size control
        model: override model name (defaults to env or gpt-4o)

    Returns:
        dict: gmail_id -> (label_or_None, confidence_float)
    """
    if not items:
        return {}

    if not openai_client or not OPENAI_API_KEY:
        return {}

    allowed_labels = get_allowed_ai_labels()
    allowed_set_lower = {lbl.lower(): lbl for lbl in allowed_labels}
    label_list = ", ".join(allowed_labels)

    payload = []
    for it in items:
        gid = (it.get("id") or "").strip()
        if not gid:
            continue
        payload.append(
            {
                "id": gid,
                "sender": (it.get("sender") or "")[:300],
                "subject": (it.get("subject") or "")[:300],
                "body": (it.get("body") or "")[:max_body_chars],
            }
        )

    if not payload:
        return {}

    system_prompt = (
        "You are an email classifier for a personal inbox. "
        "For each email, choose exactly one label from the allowed list, "
        "or 'None' if the email does not clearly fit any category. "
        "Return ONLY valid JSON."
    )

    user_prompt = (
        "Allowed labels:\n"
        f"{label_list}\n\n"
        "Classify these emails. Input is a JSON array of objects with fields: id, sender, subject, body.\n"
        "Return JSON in this EXACT format (no extra keys):\n"
        "{\n  \"results\": [\n    {\"id\": \"...\", \"label\": \"<one allowed label or None>\", \"confidence\": 0.0}\n  ]\n}\n\n"
        "Input:\n"
        f"{json.dumps(payload, ensure_ascii=False)}"
    )

    chosen_model = model or os.environ.get("OPENAI_MODEL", "gpt-4o")

    try:
        resp = openai_client.chat.completions.create(
            model=chosen_model,
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
            max_tokens=1200,
            temperature=0,
        )

        raw = (resp.choices[0].message.content or "").strip()
        raw = _strip_code_fences(raw)

        data = json.loads(raw)
        results = data.get("results") if isinstance(data, dict) else None
        if not isinstance(results, list):
            logger.warning("Bulk AI response missing 'results' list")
            return {}

        out: Dict[str, Tuple[str | None, float]] = {}
        for r in results:
            if not isinstance(r, dict):
                continue
            gid = str(r.get("id") or "").strip()
            if not gid:
                continue

            label_raw = str(r.get("label") or "").strip()
            conf_raw = r.get("confidence")
            try:
                conf = float(conf_raw) if conf_raw is not None else 0.0
            except Exception:
                conf = 0.0

            if not label_raw:
                out[gid] = (None, conf)
                continue

            norm = allowed_set_lower.get(label_raw.lower())
            if not norm or norm == "None":
                out[gid] = (None, conf)
            else:
                out[gid] = (norm, conf)

        return out

    except Exception:
        logger.exception("Error from OpenAI while suggesting bulk labels")
        return {}
