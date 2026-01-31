import os
import json
import logging
from datetime import datetime

from flask import Blueprint, render_template, jsonify, request, send_file
from googleapiclient.errors import HttpError

from db import get_db_connection, record_labeled_email, record_ai_suggestion
from gmail_client import (
    get_gmail_service_for_current_user,
    get_or_create_gmail_label,
    apply_label_to_message,
    extract_email_fields,
)
from ai_labels import DEFAULT_LL_LABELS, get_allowed_ai_labels, ai_suggest_label
from rule_learner import learn_rules_from_labeled_emails, sync_sender_email_rules_from_ll_labels

logger = logging.getLogger(__name__)

rules_bp = Blueprint("rules", __name__)

# Env-based behavior
ARCHIVE_RULE_LABELED = os.environ.get("ARCHIVE_RULE_LABELED", "true").lower() in (
    "1",
    "true",
    "yes",
    "on",
)
ARCHIVE_AI_LABELED = os.environ.get("ARCHIVE_AI_LABELED", "true").lower() in (
    "1",
    "true",
    "yes",
    "on",
)

# If true (default), when a message is labeled we REMOVE it from INBOX so it behaves
# like dragging an email into a Gmail label (it leaves Inbox, unread count drops).
REMOVE_FROM_INBOX_ON_LABEL = os.environ.get("REMOVE_FROM_INBOX_ON_LABEL", "true").lower() in (
    "1",
    "true",
    "yes",
    "on",
)

try:
    MAX_EMAILS_PER_RUN = int(os.environ.get("MAX_EMAILS_PER_RUN", "50"))
    if MAX_EMAILS_PER_RUN <= 0:
        MAX_EMAILS_PER_RUN = 50
except ValueError:
    MAX_EMAILS_PER_RUN = 50

# NEW: sender-email learning config
LL_LABEL_PREFIX = os.environ.get("LL_LABEL_PREFIX", "@LL-")
try:
    SENDER_RULES_MAX_PER_LABEL = int(os.environ.get("SENDER_RULES_MAX_PER_LABEL", "200"))
    if SENDER_RULES_MAX_PER_LABEL <= 0:
        SENDER_RULES_MAX_PER_LABEL = 200
except ValueError:
    SENDER_RULES_MAX_PER_LABEL = 200

# per your request: default false
SENDER_RULES_SKIP_FREE_DOMAINS = os.environ.get("SENDER_RULES_SKIP_FREE_DOMAINS", "false").lower() in (
    "1",
    "true",
    "yes",
    "on",
)

# Downloadable run log (single file overwritten each run)
RUN_LOG_DIR = os.environ.get("RUN_LOG_DIR", "/tmp/label-logic-runs")
RUN_LOG_FILENAME = os.environ.get("RUN_LOG_FILENAME", "last_run.jsonl")


def _run_log_path() -> str:
    os.makedirs(RUN_LOG_DIR, exist_ok=True)
    return os.path.join(RUN_LOG_DIR, RUN_LOG_FILENAME)


def _log_line(fp, obj: dict):
    fp.write(json.dumps(obj, ensure_ascii=False) + "\n")
    fp.flush()


def _utc_ts() -> str:
    return datetime.utcnow().isoformat(timespec="seconds") + "Z"


def db_row_to_rule(row):
    return {
        "id": row["id"],
        "label_name": row["label_name"],
        "from_contains": row.get("from_contains") or "",
        "subject_contains": row.get("subject_contains") or "",
        "body_contains": row.get("body_contains") or "",
        "is_active": bool(row.get("is_active")),
        "mark_as_read": bool(row.get("mark_as_read")),
    }


def load_active_rules():
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("SELECT * FROM rules WHERE is_active = TRUE ORDER BY id ASC;")
    rows = cur.fetchall()
    conn.close()
    return [db_row_to_rule(r) for r in rows]


def load_all_rules():
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("SELECT * FROM rules ORDER BY id ASC;")
    rows = cur.fetchall()
    conn.close()
    return [db_row_to_rule(r) for r in rows]


def email_matches_rule(sender, subject, body, rule):
    """
    OR logic:
      - if any of from/subject/body contains matches, rule matches.
      - if a field is blank, it doesn't participate.
      - if all are blank => no match (avoid labeling everything).
    """
    from_contains = (rule.get("from_contains") or "").strip().lower()
    subject_contains = (rule.get("subject_contains") or "").strip().lower()
    body_contains = (rule.get("body_contains") or "").strip().lower()

    if not from_contains and not subject_contains and not body_contains:
        return False

    sender_l = (sender or "").lower()
    subject_l = (subject or "").lower()
    body_l = (body or "").lower()

    if from_contains and from_contains in sender_l:
        return True
    if subject_contains and subject_contains in subject_l:
        return True
    if body_contains and body_contains in body_l:
        return True

    return False


@rules_bp.route("/", methods=["GET"])
def index():
    return render_template("dashboard.html")


@rules_bp.route("/dashboard", methods=["GET"])
def dashboard_page():
    return render_template("dashboard.html")


@rules_bp.route("/rules", methods=["GET"])
def rules_page():
    return render_template("rules.html")


@rules_bp.route("/relabel", methods=["GET"])
def relabel_page():
    return render_template("relabel.html")


@rules_bp.route("/api/allowed-ai-labels", methods=["GET"])
def api_allowed_ai_labels():
    return jsonify({"allowed_ai_labels": get_allowed_ai_labels()})


@rules_bp.route("/api/rules", methods=["GET"])
def api_get_rules():
    rules = load_all_rules()
    return jsonify(rules)


@rules_bp.route("/api/rules", methods=["POST"])
def api_create_rule():
    data = request.get_json(force=True, silent=True) or {}

    label_name = (data.get("label_name") or "").strip()
    from_contains = (data.get("from_contains") or "").strip()
    subject_contains = (data.get("subject_contains") or "").strip()
    body_contains = (data.get("body_contains") or "").strip()
    is_active = bool(data.get("is_active", True))
    mark_as_read = bool(data.get("mark_as_read", False))

    if not label_name:
        return jsonify({"error": "label_name is required"}), 400

    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute(
        """
        INSERT INTO rules (label_name, from_contains, subject_contains, body_contains, is_active, mark_as_read)
        VALUES (%s, %s, %s, %s, %s, %s)
        RETURNING id;
        """,
        (label_name, from_contains, subject_contains, body_contains, is_active, mark_as_read),
    )
    new_id = cur.fetchone()["id"]
    conn.commit()
    conn.close()

    return jsonify({"status": "ok", "id": new_id})


@rules_bp.route("/api/rules/<int:rule_id>", methods=["PUT"])
def api_update_rule(rule_id):
    data = request.get_json(force=True, silent=True) or {}

    label_name = (data.get("label_name") or "").strip()
    from_contains = (data.get("from_contains") or "").strip()
    subject_contains = (data.get("subject_contains") or "").strip()
    body_contains = (data.get("body_contains") or "").strip()
    is_active = bool(data.get("is_active", True))
    mark_as_read = bool(data.get("mark_as_read", False))

    if not label_name:
        return jsonify({"error": "label_name is required"}), 400

    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute(
        """
        UPDATE rules
        SET label_name = %s,
            from_contains = %s,
            subject_contains = %s,
            body_contains = %s,
            is_active = %s,
            mark_as_read = %s
        WHERE id = %s
        """,
        (label_name, from_contains, subject_contains, body_contains, is_active, mark_as_read, rule_id),
    )
    conn.commit()
    conn.close()

    return jsonify({"status": "ok"})


@rules_bp.route("/api/rules/<int:rule_id>", methods=["DELETE"])
def api_delete_rule(rule_id):
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("DELETE FROM rules WHERE id = %s", (rule_id,))
    conn.commit()
    conn.close()
    return jsonify({"status": "ok"})


@rules_bp.route("/api/labels", methods=["GET"])
def api_labels():
    service = get_gmail_service_for_current_user()

    # Only show user labels + CATEGORY labels you care about
    resp = service.users().labels().list(userId="me").execute()
    labels = resp.get("labels", [])

    # Keep: user labels + CATEGORY_PERSONAL + LABEL_INBOX + CATEGORY_* (optional)
    keep_ids = {
        "INBOX",
        "CATEGORY_PERSONAL",
        "CATEGORY_PROMOTIONS",
        "CATEGORY_SOCIAL",
        "CATEGORY_UPDATES",
        "CATEGORY_FORUMS",
    }

    filtered = []
    for l in labels:
        lid = l.get("id")
        ltype = l.get("type")
        if ltype == "user" or lid in keep_ids:
            filtered.append(l)

    # Fetch counts for each label
    out = []
    for l in filtered:
        lid = l.get("id")
        try:
            meta = service.users().labels().get(userId="me", id=lid).execute()
        except Exception:
            meta = l
        out.append(
            {
                "id": lid,
                "name": meta.get("name") or l.get("name") or lid,
                "messagesUnread": meta.get("messagesUnread"),
                "messagesTotal": meta.get("messagesTotal"),
            }
        )

    # Sort: inbox + categories first, then user labels alpha
    def sort_key(x):
        name = x["name"]
        lid = x["id"]
        priority = 2
        if lid == "INBOX":
            priority = 0
        elif lid.startswith("CATEGORY_"):
            priority = 1
        return (priority, name.lower())

    out.sort(key=sort_key)
    return jsonify(out)


@rules_bp.route("/api/labels/<label_id>/mark-read", methods=["POST"])
def api_mark_read(label_id):
    service = get_gmail_service_for_current_user()

    # Mark all unread in this label as read
    q = f"label:{label_id} is:unread"
    resp = service.users().messages().list(userId="me", q=q, maxResults=500).execute()
    messages = resp.get("messages", []) or []
    if not messages:
        return jsonify({"message": "No unread messages found."})

    ids = [m["id"] for m in messages]
    service.users().messages().batchModify(
        userId="me",
        body={"ids": ids, "removeLabelIds": ["UNREAD"]},
    ).execute()

    return jsonify({"message": f"Marked {len(ids)} messages as read."})


@rules_bp.route("/init-default-labels", methods=["POST"])
def init_default_labels():
    service = get_gmail_service_for_current_user()
    ensured = 0
    for name in DEFAULT_LL_LABELS:
        get_or_create_gmail_label(service, name)
        ensured += 1
    return jsonify({"status": "ok", "count": ensured})


@rules_bp.route("/learn-rules", methods=["POST"])
def learn_rules():
    created = learn_rules_from_labeled_emails()
    # optional: also sync sender-email rules based on @LL- labels
    try:
        sync_sender_email_rules_from_ll_labels(
            label_prefix=LL_LABEL_PREFIX,
            max_per_label=SENDER_RULES_MAX_PER_LABEL,
            skip_free_domains=SENDER_RULES_SKIP_FREE_DOMAINS,
        )
    except Exception:
        logger.exception("sync_sender_email_rules_from_ll_labels failed (non-fatal)")
    return jsonify({"status": "ok", "created": created})


@rules_bp.route("/download-run-log", methods=["GET"])
def download_run_log():
    path = _run_log_path()
    if not os.path.exists(path):
        return jsonify({"error": "No run log found yet."}), 404
    return send_file(path, as_attachment=True, download_name=RUN_LOG_FILENAME)


@rules_bp.route("/run-labeler", methods=["POST"])
def run_labeler():
    """
    Runs the labeler once:
    - Pulls messages from Gmail that are eligible
    - Applies rule-based labels first
    - Then AI labels
    - Logs each decision/action to a JSONL run log
    """
    service = get_gmail_service_for_current_user()

    # Only look in Category Personal
    gmail_query = "category:personal"

    rules = load_active_rules()

    processed = 0
    rule_labeled = 0
    ai_labeled = 0

    log_path = _run_log_path()
    with open(log_path, "w", encoding="utf-8") as fp:
        _log_line(fp, {"type": "run_start", "ts": _utc_ts(), "query": gmail_query, "max": MAX_EMAILS_PER_RUN})

        try:
            resp = service.users().messages().list(userId="me", q=gmail_query, maxResults=MAX_EMAILS_PER_RUN).execute()
            messages = resp.get("messages", []) or []
        except HttpError as e:
            _log_line(fp, {"type": "error", "ts": _utc_ts(), "error": str(e)})
            return jsonify({"error": str(e)}), 500

        for m in messages:
            msg_id = m.get("id")
            if not msg_id:
                continue

            processed += 1

            try:
                full = service.users().messages().get(userId="me", id=msg_id, format="full").execute()
            except HttpError as e:
                _log_line(fp, {"type": "message_error", "ts": _utc_ts(), "id": msg_id, "error": str(e)})
                continue

            # Extract fields
            sender, subject, body_text, snippet, thread_id, internal_date = extract_email_fields(full)

            # Pre-action metadata
            label_ids = set((full.get("labelIds") or []))
            is_unread = "UNREAD" in label_ids
            received_ms = full.get("internalDate")
            received_iso = None
            try:
                if received_ms:
                    received_iso = datetime.utcfromtimestamp(int(received_ms) / 1000).isoformat(timespec="seconds") + "Z"
            except Exception:
                received_iso = None

            # Determine "box" / category-ish labels present
            category_labels = [lid for lid in label_ids if lid.startswith("CATEGORY_")]
            system_boxes = []
            if "INBOX" in label_ids:
                system_boxes.append("INBOX")
            if "SPAM" in label_ids:
                system_boxes.append("SPAM")
            if "TRASH" in label_ids:
                system_boxes.append("TRASH")
            if "IMPORTANT" in label_ids:
                system_boxes.append("IMPORTANT")

            _log_line(
                fp,
                {
                    "type": "message_seen",
                    "ts": _utc_ts(),
                    "id": msg_id,
                    "thread_id": thread_id,
                    "from": sender,
                    "subject": subject,
                    "snippet": snippet,
                    "received": received_iso,
                    "unread_before": is_unread,
                    "boxes": system_boxes,
                    "categories": category_labels,
                    "labelIds": sorted(list(label_ids)),
                },
            )

            # 1) RULE LABELING
            matched_rule = None
            for r in rules:
                if email_matches_rule(sender, subject, body_text, r):
                    matched_rule = r
                    break

            if matched_rule:
                label_name = matched_rule["label_name"]
                mark_as_read = bool(matched_rule.get("mark_as_read"))

                try:
                    label_id = get_or_create_gmail_label(service, label_name)

                    add_label_ids = [label_id]
                    remove_label_ids = []
                    if mark_as_read:
                        remove_label_ids.append("UNREAD")
                    if REMOVE_FROM_INBOX_ON_LABEL:
                        remove_label_ids.append("INBOX")

                    apply_label_to_message(
                        service,
                        msg_id,
                        add_label_ids=add_label_ids,
                        remove_label_ids=remove_label_ids,
                    )

                    record_labeled_email(
                        message_id=msg_id,
                        thread_id=thread_id,
                        source="rule",
                        applied_label=label_name,
                        sender=sender,
                        subject=subject,
                        snippet=snippet,
                    )

                    rule_labeled += 1
                    _log_line(
                        fp,
                        {
                            "type": "rule_labeled",
                            "ts": _utc_ts(),
                            "id": msg_id,
                            "label_name": label_name,
                            "mark_as_read": mark_as_read,
                            "remove_from_inbox": REMOVE_FROM_INBOX_ON_LABEL,
                        },
                    )

                except Exception as e:
                    _log_line(fp, {"type": "rule_label_error", "ts": _utc_ts(), "id": msg_id, "error": str(e)})
                continue

            # 2) AI LABELING
            try:
                allowed = get_allowed_ai_labels()
                suggestion = ai_suggest_label(sender, subject, snippet, allowed_labels=allowed)
            except Exception as e:
                _log_line(fp, {"type": "ai_error", "ts": _utc_ts(), "id": msg_id, "error": str(e)})
                continue

            if not suggestion:
                _log_line(fp, {"type": "ai_no_suggestion", "ts": _utc_ts(), "id": msg_id})
                continue

            try:
                label_id = get_or_create_gmail_label(service, suggestion)

                add_label_ids = [label_id]
                remove_label_ids = []
                if ARCHIVE_AI_LABELED or REMOVE_FROM_INBOX_ON_LABEL:
                    remove_label_ids.append("INBOX")

                apply_label_to_message(
                    service,
                    msg_id,
                    add_label_ids=add_label_ids,
                    remove_label_ids=remove_label_ids,
                )

                record_ai_suggestion(
                    message_id=msg_id,
                    thread_id=thread_id,
                    suggested_label=suggestion,
                    sender=sender,
                    subject=subject,
                    snippet=snippet,
                )
                record_labeled_email(
                    message_id=msg_id,
                    thread_id=thread_id,
                    source="ai",
                    applied_label=suggestion,
                    sender=sender,
                    subject=subject,
                    snippet=snippet,
                )

                ai_labeled += 1
                _log_line(
                    fp,
                    {
                        "type": "ai_labeled",
                        "ts": _utc_ts(),
                        "id": msg_id,
                        "label_name": suggestion,
                        "archived": bool(ARCHIVE_AI_LABELED or REMOVE_FROM_INBOX_ON_LABEL),
                    },
                )

            except Exception as e:
                _log_line(fp, {"type": "ai_label_error", "ts": _utc_ts(), "id": msg_id, "error": str(e)})

        _log_line(
            fp,
            {
                "type": "run_end",
                "ts": _utc_ts(),
                "processed": processed,
                "rule_labeled": rule_labeled,
                "ai_labeled": ai_labeled,
            },
        )

    return jsonify(
        {
            "status": "ok",
            "processed": processed,
            "rule_labeled": rule_labeled,
            "ai_labeled": ai_labeled,
            "log_download_url": "/download-run-log",
        }
    )
