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


def _list_messages_for_label(service, label_id: str, max_results: int) -> List[str]:
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
    except HttpError:
        return "", ""

    headers = msg.get("payload", {}).get("headers", []) or []
    hmap = {h.get("name", "").lower(): h.get("value", "") for h in headers}
    return hmap.get("from", "") or "", hmap.get("subject", "") or ""


def learn_rules_from_labeled_emails(
    service,
    label_names: List[str],
    *,
    max_per_label: int = 200,
    min_domain_count: int = 3,
    min_token_count: int = 4,
    purity: float = 0.9,
    max_rules_per_label: int = 10,
    create_domain_rules: bool = True,
    create_subject_rules: bool = True,
) -> Dict:
    """
    Look at existing emails *already inside Gmail labels* and auto-create rules.

    Strategy (v1):
      - Domain rules: if a sender domain strongly maps to a single label, create from_contains="@domain"
      - Subject token rules: if a subject token strongly maps to a single label, create subject_contains="token"

    Returns a summary dict with counts and samples.
    """
    label_names = [ln for ln in (label_names or []) if ln]
    if not label_names:
        return {"status": "ok", "message": "No labels provided", "created": 0, "details": []}

    # Pull examples across labels
    domain_counts = defaultdict(Counter)   # domain -> Counter(label -> count)
    token_counts = defaultdict(Counter)    # token  -> Counter(label -> count)
    label_sample_counts = Counter()        # label -> total sampled

    details = []

    for label_name in label_names:
        label_id = _get_label_id_by_name(service, label_name)
        if not label_id:
            details.append({"label": label_name, "sampled": 0, "warning": "Label not found in Gmail"})
            continue

        try:
            msg_ids = _list_messages_for_label(service, label_id, max_per_label)
        except HttpError as e:
            logger.exception("Failed listing messages for label %s", label_name)
            details.append({"label": label_name, "sampled": 0, "error": str(e)})
            continue

        sampled = 0
        for mid in msg_ids:
            from_h, subj = _get_from_subject(service, mid)
            if not from_h and not subj:
                continue
            sampled += 1

            d = _sender_domain(from_h)
            if d:
                domain_counts[d][label_name] += 1

            for tok in _tokenize_subject(subj):
                token_counts[tok][label_name] += 1

        label_sample_counts[label_name] += sampled
        details.append({"label": label_name, "sampled": sampled})

    # Decide which rules to create
    created = 0
    created_rules = []

    def pick_label(counter: Counter, min_count: int):
        total = sum(counter.values())
        if total < min_count:
            return "", 0, total, 0.0
        label, top = counter.most_common(1)[0]
        share = top / total if total else 0.0
        if share >= purity:
            return label, top, total, share
        return "", top, total, share

    # Domain rules
    if create_domain_rules:
        for domain, cnts in sorted(domain_counts.items(), key=lambda kv: sum(kv[1].values()), reverse=True):
            label, top, total, share = pick_label(cnts, min_domain_count)
            if not label:
                continue

            fc = f"@{domain}"
            if _insert_rule(label, from_contains=fc):
                created += 1
                created_rules.append(
                    {
                        "type": "from",
                        "label": label,
                        "from_contains": fc,
                        "support": top,
                        "total": total,
                        "purity": round(share, 3),
                    }
                )

    # Subject token rules
    if create_subject_rules:
        per_label_created = Counter()
        for token, cnts in sorted(token_counts.items(), key=lambda kv: sum(kv[1].values()), reverse=True):
            label, top, total, share = pick_label(cnts, min_token_count)
            if not label:
                continue
            if per_label_created[label] >= max_rules_per_label:
                continue

            sc = token
            if _insert_rule(label, subject_contains=sc):
                created += 1
                per_label_created[label] += 1
                created_rules.append(
                    {
                        "type": "subject",
                        "label": label,
                        "subject_contains": sc,
                        "support": top,
                        "total": total,
                        "purity": round(share, 3),
                    }
                )

    return {
        "status": "ok",
        "labels_considered": label_names,
        "samples": dict(label_sample_counts),
        "created": created,
        "created_rules": created_rules[:200],  # cap response size
        "details": details,
        "params": {
            "max_per_label": max_per_label,
            "min_domain_count": min_domain_count,
            "min_token_count": min_token_count,
            "purity": purity,
            "max_rules_per_label": max_rules_per_label,
        },
    }
