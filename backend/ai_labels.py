import os
import json
import logging
import re
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


# -----------------------------
# Allowed labels
# -----------------------------


def get_dynamic_ll_labels_from_db():
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("SELECT DISTINCT label_name FROM rules WHERE label_name LIKE '@LL-%';")
        rows = cur.fetchall()
        conn.close()
        return [r["label_name"] for r in rows if r.get("label_name")]
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


# -----------------------------
# Single email AI (fallback)
# -----------------------------


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


# -----------------------------
# Bulk AI helpers
# -----------------------------


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


def _remove_illegal_control_chars(s: str) -> str:
    """
    JSON strings cannot contain raw control characters U+0000 through U+001F.
    This can happen if the model outputs them or copies them from content.
    """
    if not s:
        return ""
    return re.sub(r"[\x00-\x1F]", "", s)


def _extract_first_json_object(s: str) -> str:
    """
    Extract the first {...} JSON object block from a string.
    Helps when the model adds extra text before/after the JSON.
    """
    if not s:
        return ""
    start = s.find("{")
    end = s.rfind("}")
    if start == -1 or end == -1 or end <= start:
        return ""
    return s[start : end + 1]


def _safe_json_loads(raw: str) -> dict | None:
    """
    Try to parse JSON robustly:
      1) direct json.loads
      2) strip code fences + remove control chars
      3) extract first {...} block + remove control chars
    """
    if not raw:
        return None

    # Attempt 1: direct
    try:
        data = json.loads(raw)
        return data if isinstance(data, dict) else None
    except Exception:
        pass

    # Attempt 2: strip fences + remove control chars
    cleaned = _remove_illegal_control_chars(_strip_code_fences(raw))
    try:
        data = json.loads(cleaned)
        return data if isinstance(data, dict) else None
    except Exception:
        pass

    # Attempt 3: extract json object block
    extracted = _extract_first_json_object(cleaned)
    if extracted:
        try:
            data = json.loads(extracted)
            return data if isinstance(data, dict) else None
        except Exception:
            pass

    return None


def ai_suggest_labels_bulk(
    items: List[Dict[str, str]],
    *,
    max_body_chars: int = 700,
    model: str | None = None,
) -> Dict[str, Tuple[str | None, float]]:
    """
    Classify many emails in a SINGLE OpenAI call.

    Returns:
      dict: gmail_id -> (label_or_None, confidence_float)
    """
    if not items:
        return {}

    if not openai_client or not OPENAI_API_KEY:
        return {}

    allowed_labels = get_allowed_ai_labels()
    allowed_map_lower = {lbl.lower(): lbl for lbl in allowed_labels}
    label_list = ", ".join(allowed_labels)

    payload = []
    for it in items:
        gid = (it.get("id") or "").strip()
        if not gid:
            continue
        payload.append(
            {
                "id": gid,
                "sender": (it.get("sender") or "")[:240],
                "subject": (it.get("subject") or "")[:240],
                "body": (it.get("body") or "")[:max_body_chars],
            }
        )

    if not payload:
        return {}

    chosen_model = model or os.environ.get("OPENAI_MODEL", "gpt-4o")

    # Keep the instruction very tight to reduce "helpful" extra text.
    system_prompt = (
        "You are an email classifier. "
        "You MUST return ONLY a valid JSON object. No prose, no markdown. "
        "For each email, choose exactly one label from the allowed list, "
        "or 'None' if it does not clearly fit."
    )

    user_prompt = (
        "Allowed labels:\n"
        f"{label_list}\n\n"
        "Input is a JSON array of objects with fields: id, sender, subject, body.\n"
        "Return a JSON OBJECT with this exact shape:\n"
        "{\n"
        "  \"results\": [\n"
        "    {\"id\": \"<id>\", \"label\": \"<allowed label or None>\", \"confidence\": 0.0}\n"
        "  ]\n"
        "}\n\n"
        "Input:\n"
        f"{json.dumps(payload, ensure_ascii=False)}"
    )

    # -----------------------------
    # Call OpenAI (prefer strict JSON mode)
    # -----------------------------
    try:
        # Many modern models support response_format for strict JSON output.
        # If not supported, this will raise TypeError and we fall back.
        resp = openai_client.chat.completions.create(
            model=chosen_model,
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
            temperature=0,
            max_tokens=1600,
            response_format={"type": "json_object"},
        )
        raw = (resp.choices[0].message.content or "").strip()
    except TypeError:
        # Older models/SDK combinations may not accept response_format.
        resp = openai_client.chat.completions.create(
            model=chosen_model,
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
            temperature=0,
            max_tokens=1600,
        )
        raw = (resp.choices[0].message.content or "").strip()
    except Exception:
        logger.exception("Error from OpenAI while suggesting bulk labels (request failed)")
        return {}

    # -----------------------------
    # Robust parse
    # -----------------------------
    data = _safe_json_loads(raw)
    if not data:
        logger.error("Bulk AI response was not valid JSON. Raw (truncated): %r", raw[:500])
        return {}

    results = data.get("results")
    if not isinstance(results, list):
        logger.warning("Bulk AI JSON missing 'results' list. Keys=%s", list(data.keys()))
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

        norm = allowed_map_lower.get(label_raw.lower())
        if not norm or norm == "None":
            out[gid] = (None, conf)
        else:
            out[gid] = (norm, conf)

    return out
