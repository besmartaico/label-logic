import logging
import os
import re
from collections import Counter, defaultdict
from email.utils import parseaddr
from typing import Dict, List, Tuple

from googleapiclient.errors import HttpError

from db import get_db_connection

logger = logging.getLogger(__name__)

# A small stopword list for subject token suggestions
STOPWORDS = {
    "a", "an", "and", "are", "as", "at", "be", "but", "by", "can", "could", "did", "do", "does",
    "for", "from", "has", "have", "how", "i", "in", "is", "it", "its", "just", "me", "my",
    "of", "on", "or", "our", "re", "so", "that", "the", "their", "there", "this", "to", "up",
    "we", "were", "what", "when", "where", "who", "why", "with", "you", "your",
    "fw", "fwd", "vs", "no", "yes"
}

EMAIL_RE = re.compile(r"@([\w\.-]+)")
TOKEN_RE = re.compile(r"[a-z0-9][a-z0-9\-]{2,}")  # min len ~3

SENDER_EMAIL_RE = re.compile(r"([A-Z0-9._%+\-]+@[A-Z0-9.\-]+\.[A-Z]{2,})", re.IGNORECASE)


# -----------------------------
# Existing v1 helpers (domain + subject token learning)
# -----------------------------


def _sender_domain(from_field: str) -> str:
    """
    Extract full domain from a From header. Returns "" if unavailable.
    Example: 'Bob <bob@acme.co>' -> 'acme.co'
    """
    _, email = parseaddr(from_field or "")
    m = EMAIL_RE.search(email or "")
    if not m:
        return ""
    domain = (m.group(1) or "").lower().strip(".")
    return domain


def _tokenize_subject(subject: str) -> List[str]:
    """
    Tokenize subject into lowercase alphanum/hyphen tokens.
    Filters stopwords and very short tokens.
    """
    s = (subject or "").lower()
    toks = TOKEN_RE.findall(s)
    out = []
    for t in toks:
        if t in STOPWORDS:
            continue
        # ignore numeric-only tokens like "12345"
        if t.isdigit():
            continue
        out.append(t)
    return out


def _rule_exists(label_name: str, from_contains: str, subject_contains: str, body_contains: str) -> bool:
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute(
        """
        SELECT 1
        FROM rules
        WHERE label_name = %s
          AND COALESCE(from_contains,'') = %s
          AND COALESCE(subject_contains,'') = %s
          AND COALESCE(body_contains,'') = %s
        LIMIT 1;
        """,
        (label_name, from_contains or "", subject_contains or "", body_contains or ""),
    )
    row = cur.fetchone()
    conn.close()
    return bool(row)


def _insert_rule(
    label_name: str,
    from_contains: str = "",
    subject_contains: str = "",
    body_contains: str = "",
    is_active: bool = True,
    mark_as_read: bool = False,
) -> int:
    """
    Insert rule if not exists. Returns 1 if inserted, 0 if skipped.
    """
    if _rule_exists(label_name, from_contains, subject_contains, body_contains):
        return 0

    from datetime import datetime
    now = datetime.utcnow().isoformat(timespec="seconds")

    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute(
        """
        INSERT INTO rules
          (label_name, from_contains, subject_contains, body_contains,
           is_active, mark_as_read, created_at, updated_at)
        VALUES
          (%s, %s, %s, %s, %s, %s, %s, %s);
        """,
        (
            label_name,
            (from_contains or "").strip() or None,
            (subject_contains or "").strip() or None,
            (body_contains or "").strip() or None,
            bool(is_active),
            bool(mark_as_read),
            now,
            now,
        ),
    )
    conn.commit()
    conn.close()
    return 1


def _get_label_id_by_name(service, label_name: str) -> str:
    """
    Return Gmail label id for a label name. Empty string if not found.
    """
    resp = service.users().labels().list(userId="me").execute()
    for lbl in resp.get("labels", []):
        if (lbl.get("name") or "") == label_name:
            return lbl.get("id") or ""
    return ""


def _list_messages_for_label(service, label_id: str, max_results: int, q_filter: str | None = None) -> List[str]:
    ids = []
    page_token = None
    user_id = "me"

    while True:
        resp = (
            service.users()
            .messages()
            .list(
                userId=user_id,
                labelIds=[label_id],
                q=q_filter,
                maxResults=min(500, max_results - len(ids)),
                pageToken=page_token,
            )
            .execute()
        )
        ids.extend([m["id"] for m in resp.get("messages", []) if m.get("id")])
        page_token = resp.get("nextPageToken")
        if not page_token or len(ids) >= max_results:
            break

    return ids[:max_results]


def _get_from_subject(service, gmail_id: str) -> Tuple[str, str]:
    """
    Fetch message metadata and return (from, subject). Empty strings on failure.
    """
    try:
        msg = (
            service.users()
            .messages()
            .get(
                userId="me",
                id=gmail_id,
                format="metadata",
                metadataHeaders=["From", "Subject"],
            )
            .execute()
        )
        headers = msg.get("payload", {}).get("headers", []) or []
        from_h = ""
        subj_h = ""
        for h in headers:
            name = (h.get("name") or "").lower()
            if name == "from":
                from_h = h.get("value") or ""
            elif name == "subject":
                subj_h = h.get("value") or ""
        return from_h, subj_h
    except Exception:
        logger.exception("Failed _get_from_subject(%s)", gmail_id)
        return "", ""


def learn_rules_from_labeled_emails(
    service,
    allowed_labels: List[str],
    max_per_label: int = 50,
    min_domain_count: int = 3,
    min_subject_token_count: int = 3,
) -> int:
    """
    Look at emails inside each allowed label and propose new rules.
    Currently learns:
      - Domain rules: from_contains="@domain.com"
      - Subject token rules: subject_contains="invoice"
    """
    created = 0

    label_resp = service.users().labels().list(userId="me").execute()
    all_labels = label_resp.get("labels", [])

    allowed_set = set(allowed_labels or [])
    allowed_label_ids = []
    for lbl in all_labels:
        if (lbl.get("name") or "") in allowed_set:
            allowed_label_ids.append((lbl.get("id"), lbl.get("name")))

    for label_id, label_name in allowed_label_ids:
        msg_ids = _list_messages_for_label(service, label_id, max_per_label)

        domains = Counter()
        tokens = Counter()

        for mid in msg_ids:
            from_h, subj = _get_from_subject(service, mid)
            dom = _sender_domain(from_h)
            if dom:
                domains[dom] += 1
            for t in _tokenize_subject(subj):
                tokens[t] += 1

        # Domain rules
        for dom, cnt in domains.items():
            if cnt >= min_domain_count:
                created += _insert_rule(label_name, from_contains=f"@{dom}")

        # Subject token rules
        for tok, cnt in tokens.items():
            if cnt >= min_subject_token_count:
                created += _insert_rule(label_name, subject_contains=tok)

    return created


# -----------------------------
# NEW: sender-email learning from @LL-* labels (exact sender)
# -----------------------------


def _list_ll_labels(service, label_prefix: str) -> List[Dict]:
    resp = service.users().labels().list(userId="me").execute()
    labels = resp.get("labels", []) or []
    out = []
    for lbl in labels:
        name = (lbl.get("name") or "")
        if name.startswith(label_prefix):
            out.append(lbl)
    return out


def _extract_sender_email(from_header: str) -> str:
    if not from_header:
        return ""
    m = SENDER_EMAIL_RE.search(from_header)
    return (m.group(1) or "").strip().lower() if m else ""


def _get_from_and_internal_date(service, gmail_id: str) -> Tuple[str, int]:
    """
    Fetch message metadata and return (from_header, internalDate_ms).
    Uses metadata-only fetch for speed.
    """
    try:
        msg = (
            service.users()
            .messages()
            .get(
                userId="me",
                id=gmail_id,
                format="metadata",
                metadataHeaders=["From"],
            )
            .execute()
        )
        internal_ms = int(msg.get("internalDate") or 0)
        headers = msg.get("payload", {}).get("headers", []) or []
        from_h = ""
        for h in headers:
            if (h.get("name") or "").lower() == "from":
                from_h = h.get("value") or ""
                break
        return from_h, internal_ms
    except Exception:
        logger.exception("Failed _get_from_and_internal_date(%s)", gmail_id)
        return "", 0


def _upsert_sender_email_rule_latest_wins(sender_email: str, label_name: str) -> int:
    """
    Upsert behavior:
      - if a rule exists with from_contains == sender_email, update its label_name to the latest label_name
      - else insert it
    Returns 1 if inserted/updated, 0 if no change.
    """
    from datetime import datetime
    now = datetime.utcnow().isoformat(timespec="seconds")

    conn = get_db_connection()
    cur = conn.cursor()

    cur.execute(
        """
        SELECT id, label_name
        FROM rules
        WHERE COALESCE(from_contains,'') = %s
        LIMIT 1;
        """,
        (sender_email,),
    )
    row = cur.fetchone()

    if not row:
        cur.execute(
            """
            INSERT INTO rules
              (label_name, from_contains, subject_contains, body_contains,
               is_active, mark_as_read, created_at, updated_at)
            VALUES
              (%s, %s, NULL, NULL, TRUE, FALSE, %s, %s);
            """,
            (label_name, sender_email, now, now),
        )
        conn.commit()
        conn.close()
        return 1

    rule_id = row["id"]
    existing_label = row["label_name"]

    if (existing_label or "") != label_name:
        cur.execute(
            """
            UPDATE rules
            SET label_name=%s,
                updated_at=%s
            WHERE id=%s;
            """,
            (label_name, now, rule_id),
        )
        conn.commit()
        conn.close()
        return 1

    conn.close()
    return 0


def sync_sender_email_rules_from_ll_labels(
    service,
    *,
    label_prefix: str = "@LL-",
    max_per_label: int = 200,
    skip_free_email_domains: bool = False,  # per your request
    lookback_days: int = 1,
) -> Dict:
    """
    Scan all Gmail labels starting with @LL- and create/update sender-email rules.

    Performance: you can limit scanning to only messages from the last N days via lookback_days.
    Set lookback_days=0 to disable the filter (scan all messages).

    Rule format:
      from_contains = "john@vendor.com"   (exact sender email)
      label_name    = "@LL-Something"

    "Latest manual placement wins":
      - If sender appears in multiple @LL- labels, we choose the label for the most recent message (by internalDate).
      - We upsert/update the existing rule to match that label.

    Returns summary dict.
    """
    free_domains = {
        "gmail.com", "googlemail.com",
        "outlook.com", "hotmail.com", "live.com",
        "yahoo.com",
        "icloud.com",
        "aol.com",
        "proton.me", "protonmail.com",
    }

    try:
        ll_labels = _list_ll_labels(service, label_prefix)
    except HttpError as e:
        return {"status": "error", "error": f"Failed to list Gmail labels: {e}"}

    if not ll_labels:
        return {
            "status": "ok",
            "message": f"No labels found starting with {label_prefix}",
            "created_or_updated": 0,
            "unique_senders_considered": 0,
            "details": [],
        }

    # sender_email -> (latest_internalDate_ms, label_name)
    latest_map: Dict[str, Tuple[int, str]] = {}

    details = []
    total_sampled = 0

    for lbl in ll_labels:
        label_name = lbl.get("name") or ""
        label_id = lbl.get("id") or ""
        if not label_id:
            continue

        try:
            q_filter = None
            try:
                lb = int(lookback_days)
            except Exception:
                lb = 1
            if lb and lb > 0:
                q_filter = f"newer_than:{lb}d"
            msg_ids = _list_messages_for_label(service, label_id, max_per_label, q_filter=q_filter)
        except HttpError as e:
            logger.exception("Failed listing messages for label %s", label_name)
            details.append({"label": label_name, "sampled": 0, "candidates": 0, "error": str(e)})
            continue

        sampled = 0
        candidates = 0

        for mid in msg_ids:
            sampled += 1
            from_h, internal_ms = _get_from_and_internal_date(service, mid)
            sender_email = _extract_sender_email(from_h)
            if not sender_email:
                continue

            if skip_free_email_domains:
                dom = sender_email.split("@", 1)[1].lower().strip(".")
                if dom in free_domains:
                    continue

            candidates += 1
            prev = latest_map.get(sender_email)
            if not prev or internal_ms > prev[0]:
                latest_map[sender_email] = (internal_ms, label_name)

        total_sampled += sampled
        details.append({"label": label_name, "sampled": sampled, "candidates": candidates})

    created_or_updated = 0
    for sender_email, (_ts, label_name) in latest_map.items():
        created_or_updated += _upsert_sender_email_rule_latest_wins(sender_email, label_name)

    return {
        "status": "ok",
        "created_or_updated": created_or_updated,
        "unique_senders_considered": len(latest_map),
        "total_messages_sampled": total_sampled,
        "details": details,
        "lookback_days": lookback_days,
    }
