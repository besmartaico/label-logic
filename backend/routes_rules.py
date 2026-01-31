import os
import json
import logging
from datetime import datetime, timezone

try:
    # Python 3.9+
    from zoneinfo import ZoneInfo
except Exception:  # pragma: no cover
    ZoneInfo = None

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


def _extract_gmail_categories(label_ids):
    """Return Gmail category labels (e.g., CATEGORY_PERSONAL) from a labelIds list."""
    if not label_ids:
        return []
    return sorted([lid for lid in label_ids if isinstance(lid, str) and lid.startswith("CATEGORY_")])


def _human_received_at(full_message: dict) -> str:
    """Convert Gmail internalDate (ms since epoch) to a human-readable local timestamp."""
    internal_ms = full_message.get("internalDate")
    if not internal_ms:
        return ""

    try:
        ms = int(internal_ms)
    except Exception:
        return ""

    dt_utc = datetime.fromtimestamp(ms / 1000.0, tz=timezone.utc)

    # Prefer the app/user timezone for readability. Default to America/Los_Angeles.
    tzname = os.environ.get("APP_TIMEZONE", "America/Los_Angeles")
    if ZoneInfo is not None:
        try:
            dt_local = dt_utc.astimezone(ZoneInfo(tzname))
        except Exception:
            dt_local = dt_utc
    else:
        dt_local = dt_utc

    # Example: 2026-01-30 21:15:03 PST
    return dt_local.strftime("%Y-%m-%d %H:%M:%S %Z")


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
    return render_template("index.html")


@rules_bp.route("/rules", methods=["GET"])
def rules_page():
    return render_template("rules.html")


@rules_bp.route("/relabel", methods=["GET"])
def relabel_page():
    return render_template("relabel.html")


@rules_bp.route("/api/allowed-ai-labels", methods=["GET"])
def api_allowed_ai_labels():
    # returns ["@LL-...", ...]
    return jsonify({"labels": get_allowed_ai_labels()})


@rules_bp.route("/api/rules", methods=["GET"])
def api_get_rules():
    rules = load_all_rules()
    return jsonify({"rules": rules})


@rules_bp.route("/api/rules", methods=["POST"])
def api_create_rule():
    data = request.get_json(force=True) or {}
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
    data = request.get_json(force=True) or {}
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
           SET label_name=%s,
               from_contains=%s,
               subject_contains=%s,
               body_contains=%s,
               is_active=%s,
               mark_as_read=%s
         WHERE id=%s;
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
    cur.execute("DELETE FROM rules WHERE id=%s;", (rule_id,))
    conn.commit()
    conn.close()
    return jsonify({"status": "ok"})


@rules_bp.route("/download-run-log", methods=["GET"])
def download_run_log():
    """Download the most recent run log. The file is overwritten each run."""
    path = _run_log_path()
    if not os.path.exists(path):
        return jsonify({"error": "No run log available yet."}), 404
    return send_file(
        path,
        as_attachment=True,
        download_name="label_logic_last_run.jsonl",
        mimetype="application/json",
    )


@rules_bp.route("/run-labeler", methods=["POST"])
def run_labeler():
    try:
        service = get_gmail_service_for_current_user()
    except RuntimeError as e:
        return jsonify({"error": str(e)}), 401
    except Exception as e:
        logger.exception("Gmail auth failed in run_labeler")
        return jsonify({"error": f"Gmail auth failed: {e}"}), 500

    # ✅ NEW STEP 0: Learn sender-email rules from ANY @LL-* labels (latest wins)
    sender_sync_summary = {"status": "skipped", "created_or_updated": 0}
    try:
        sender_sync_summary = sync_sender_email_rules_from_ll_labels(
            service,
            label_prefix=LL_LABEL_PREFIX,
            max_per_label=SENDER_RULES_MAX_PER_LABEL,
            skip_free_email_domains=SENDER_RULES_SKIP_FREE_DOMAINS,  # default false per your request
        )
        logger.info("Sender-email rule sync summary: %s", sender_sync_summary)
    except Exception:
        logger.exception("Sender-email rule sync failed; continuing with existing rules/AI.")

    # Reload rules AFTER learning, so new sender rules apply immediately in this run
    rules = load_active_rules()
    rule_count = 0
    ai_count = 0
    total = 0

    # Write a fresh run log (single file overwritten each run)
    log_path = _run_log_path()
    try:
        fp = open(log_path, "w", encoding="utf-8")
    except Exception:
        fp = None
        logger.exception("Failed to open run log at %s", log_path)

    if fp:
        _log_line(
            fp,
            {
                "ts": _utc_ts(),
                "event": "run_start",
                "max_emails_per_run": MAX_EMAILS_PER_RUN,
                "remove_from_inbox_on_label": REMOVE_FROM_INBOX_ON_LABEL,
                "archive_rule_labeled_env": ARCHIVE_RULE_LABELED,
                "archive_ai_labeled_env": ARCHIVE_AI_LABELED,
            },
        )

    try:
        msg_list = (
            service.users()
            .messages()
            .list(userId="me", labelIds=["INBOX"], maxResults=MAX_EMAILS_PER_RUN)
            .execute()
        )
        messages = msg_list.get("messages", [])
    except HttpError as e:
        logger.exception("Gmail list failed in run_labeler")
        return jsonify({"error": f"Gmail list failed: {e}"}), 500

    for m in messages:
        gmail_id = m["id"]
        total += 1

        try:
            full = (
                service.users()
                .messages()
                .get(userId="me", id=gmail_id, format="full")
                .execute()
            )
        except HttpError:
            logger.exception("Error fetching full message in run_labeler")
            continue

        sender, subject, snippet, body = extract_email_fields(full)
        thread_id = full.get("threadId", "")

        # Capture the message's state BEFORE we modify labels
        pre_label_ids = full.get("labelIds", []) or []
        pre_categories = _extract_gmail_categories(pre_label_ids)
        received_at = _human_received_at(full)

        matched_label = None
        matched_rule_mark_read = False

        for rule in rules:
            if email_matches_rule(sender, subject, body, rule):
                matched_label = rule["label_name"]
                matched_rule_mark_read = rule.get("mark_as_read", False)
                apply_label_to_message(
                    service,
                    gmail_id,
                    matched_label,
                    remove_from_inbox=REMOVE_FROM_INBOX_ON_LABEL,
                    mark_as_read=matched_rule_mark_read,
                )
                record_labeled_email(
                    gmail_id,
                    thread_id,
                    sender,
                    subject,
                    snippet,
                    matched_label,
                    is_ai_labeled=False,
                    source="rule",
                )
                if fp:
                    _log_line(
                        fp,
                        {
                            "ts": _utc_ts(),
                            "event": "labeled",
                            "gmail_id": gmail_id,
                            "thread_id": thread_id,
                            "received_at": received_at,
                            "pre_categories": pre_categories,
                            "sender": sender,
                            "subject": subject,
                            "label": matched_label,
                            "method": "rule",
                            "removed_from_inbox": REMOVE_FROM_INBOX_ON_LABEL,
                            "marked_as_read": bool(matched_rule_mark_read),
                        },
                    )
                rule_count += 1
                break

        if not matched_label:
            label, conf = ai_suggest_label(sender, subject, body)
            if label:
                apply_label_to_message(
                    service,
                    gmail_id,
                    label,
                    remove_from_inbox=REMOVE_FROM_INBOX_ON_LABEL,
                    mark_as_read=False,
                )
                record_labeled_email(
                    gmail_id,
                    thread_id,
                    sender,
                    subject,
                    snippet,
                    label,
                    is_ai_labeled=True,
                    source="ai",
                )
                record_ai_suggestion(gmail_id, label, conf)
                if fp:
                    _log_line(
                        fp,
                        {
                            "ts": _utc_ts(),
                            "event": "labeled",
                            "gmail_id": gmail_id,
                            "thread_id": thread_id,
                            "received_at": received_at,
                            "pre_categories": pre_categories,
                            "sender": sender,
                            "subject": subject,
                            "label": label,
                            "method": "ai",
                            "confidence": conf,
                            "removed_from_inbox": REMOVE_FROM_INBOX_ON_LABEL,
                            "marked_as_read": False,
                        },
                    )
                ai_count += 1

    if fp:
        _log_line(
            fp,
            {
                "ts": _utc_ts(),
                "event": "run_end",
                "processed": total,
                "rule_labeled": rule_count,
                "ai_labeled": ai_count,
            },
        )
        fp.close()

    logger.info(
        "run_labeler finished: processed=%d rule_labeled=%d ai_labeled=%d",
        total,
        rule_count,
        ai_count,
    )

    return jsonify(
        {
            "status": "ok",
            "processed": total,
            "rule_labeled": rule_count,
            "ai_labeled": ai_count,
            "sender_rule_sync": sender_sync_summary,
            "log_download_url": "/download-run-log",
        }
    )


@rules_bp.route("/init-default-labels", methods=["GET", "POST"])
def init_default_labels():
    try:
        service = get_gmail_service_for_current_user()
    except RuntimeError as e:
        return jsonify({"error": str(e)}), 401
    except Exception as e:
        logger.exception("Gmail auth failed in init_default_labels")
        return jsonify({"error": f"Gmail auth failed: {e}"}), 500

    ensured = []

    for name in DEFAULT_LL_LABELS:
        label_id = get_or_create_gmail_label(service, name)
        label_id = get_or_create_gmail_label(service, name)
        if label_id:
            ensured.append({"name": name, "id": label_id})

    return jsonify({"status": "ok", "count": len(ensured), "ensured_labels": ensured})


@rules_bp.route("/learn-rules", methods=["POST"])
def learn_rules():
    try:
        created = learn_rules_from_labeled_emails()
        return jsonify({"status": "ok", "created": created})
    except Exception:
        logger.exception("learn_rules failed")
        return jsonify({"error": "learn_rules failed"}), 500
