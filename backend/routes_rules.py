import os
import logging
from datetime import datetime

from flask import Blueprint, render_template, jsonify, request
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

try:
    SENDER_RULES_LOOKBACK_DAYS = int(os.environ.get("SENDER_RULES_LOOKBACK_DAYS", "1"))
    if SENDER_RULES_LOOKBACK_DAYS < 0:
        SENDER_RULES_LOOKBACK_DAYS = 0
except ValueError:
    SENDER_RULES_LOOKBACK_DAYS = 1

# per your request: default false
SENDER_RULES_SKIP_FREE_DOMAINS = os.environ.get("SENDER_RULES_SKIP_FREE_DOMAINS", "false").lower() in (
    "1",
    "true",
    "yes",
    "on",
)



# -----------------------------
# Helpers
# -----------------------------


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
    cur.execute(
        """
        SELECT * FROM rules
        WHERE is_active = TRUE
        ORDER BY id;
        """
    )
    rows = cur.fetchall()
    conn.close()
    return [db_row_to_rule(r) for r in rows]


def email_matches_rule(sender, subject, body, rule):
    from_contains = (rule.get("from_contains") or "").strip().lower()
    subject_contains = (rule.get("subject_contains") or "").strip().lower()
    body_contains = (rule.get("body_contains") or "").strip().lower()

    s = (sender or "").lower()
    subj = (subject or "").lower()
    b = (body or "").lower()

    if from_contains and from_contains not in s:
        return False
    if subject_contains and subject_contains not in subj:
        return False
    if body_contains and body_contains not in b:
        return False
    return True


# -----------------------------
# Debug
# -----------------------------


@rules_bp.route("/debug/rules-count", methods=["GET"])
def debug_rules_count():
    """
    Quick sanity check: how many rules are in the DB?
    If this returns 0 active rules, then 'Rules applied: 0' is expected.
    """
    conn = get_db_connection()
    cur = conn.cursor()

    cur.execute("SELECT COUNT(*) AS cnt FROM rules;")
    total = cur.fetchone()["cnt"]

    cur.execute("SELECT COUNT(*) AS cnt FROM rules WHERE is_active = TRUE;")
    active = cur.fetchone()["cnt"]

    conn.close()
    return jsonify({"total_rules": total, "active_rules": active})



@rules_bp.route("/learn-rules", methods=["POST"])
def learn_rules():
    """
    Learn rules by looking at existing emails already inside Gmail labels, then auto-create
    rules in the rules table.

    This is the "learning loop" that lets the system improve from how your mailbox is already organized.
    """
    from flask import session, redirect, url_for

    if "google_user_id" not in session:
        return redirect(url_for("misc.auth_google"))

    try:
        service = get_gmail_service_for_current_user()
    except RuntimeError as e:
        return jsonify({"error": str(e)}), 401
    except Exception as e:
        logger.exception("Gmail auth failed in learn_rules")
        return jsonify({"error": f"Gmail auth failed: {e}"}), 500

    # Learning parameters (env-configurable)
    try:
        max_per_label = int(os.environ.get("LEARN_MAX_PER_LABEL", "50"))
    except ValueError:
        max_per_label = 50

    allowed_labels = get_allowed_ai_labels()
    created = learn_rules_from_labeled_emails(service, allowed_labels=allowed_labels, max_per_label=max_per_label)

    return jsonify({"status": "ok", "created": created})



@rules_bp.route("/rules", methods=["GET"])
def rules_page():
    rules = load_active_rules()
    return render_template("rules.html", rules=rules, default_ll_labels=DEFAULT_LL_LABELS, allowed_labels=get_allowed_ai_labels())



@rules_bp.route("/api/rules", methods=["GET"])
def api_rules():
    return jsonify(load_active_rules())



@rules_bp.route("/api/rules", methods=["POST"])
def api_create_rule():
    payload = request.get_json(force=True) or {}
    label_name = (payload.get("label_name") or "").strip()
    from_contains = (payload.get("from_contains") or "").strip()
    subject_contains = (payload.get("subject_contains") or "").strip()
    body_contains = (payload.get("body_contains") or "").strip()
    is_active = bool(payload.get("is_active", True))
    mark_as_read = bool(payload.get("mark_as_read", False))

    if not label_name:
        return jsonify({"error": "label_name is required"}), 400

    conn = get_db_connection()
    cur = conn.cursor()

    now = datetime.utcnow().isoformat(timespec="seconds")
    cur.execute(
        """
        INSERT INTO rules
          (label_name, from_contains, subject_contains, body_contains,
           is_active, mark_as_read, created_at, updated_at)
        VALUES
          (%s, %s, %s, %s, %s, %s, %s, %s)
        RETURNING id;
        """,
        (
            label_name,
            from_contains or None,
            subject_contains or None,
            body_contains or None,
            is_active,
            mark_as_read,
            now,
            now,
        ),
    )
    new_id = cur.fetchone()["id"]
    conn.commit()
    conn.close()

    return jsonify({"status": "ok", "id": new_id})



@rules_bp.route("/api/rules/<int:rule_id>", methods=["PUT"])
def api_update_rule(rule_id: int):
    payload = request.get_json(force=True) or {}

    label_name = (payload.get("label_name") or "").strip()
    from_contains = (payload.get("from_contains") or "").strip()
    subject_contains = (payload.get("subject_contains") or "").strip()
    body_contains = (payload.get("body_contains") or "").strip()
    is_active = bool(payload.get("is_active", True))
    mark_as_read = bool(payload.get("mark_as_read", False))

    if not label_name:
        return jsonify({"error": "label_name is required"}), 400

    conn = get_db_connection()
    cur = conn.cursor()

    now = datetime.utcnow().isoformat(timespec="seconds")
    cur.execute(
        """
        UPDATE rules
        SET label_name=%s,
            from_contains=%s,
            subject_contains=%s,
            body_contains=%s,
            is_active=%s,
            mark_as_read=%s,
            updated_at=%s
        WHERE id=%s;
        """,
        (
            label_name,
            from_contains or None,
            subject_contains or None,
            body_contains or None,
            is_active,
            mark_as_read,
            now,
            rule_id,
        ),
    )

    conn.commit()
    conn.close()

    return jsonify({"status": "ok"})



@rules_bp.route("/api/rules/<int:rule_id>", methods=["DELETE"])
def api_delete_rule(rule_id: int):
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("DELETE FROM rules WHERE id=%s;", (rule_id,))
    conn.commit()
    conn.close()
    return jsonify({"status": "ok"})



@rules_bp.route("/api/labels", methods=["GET"])
def api_labels():
    """
    Returns allowed AI labels + default labels. Frontend uses this to build dropdowns.
    """
    return jsonify({"default_labels": DEFAULT_LL_LABELS, "allowed_labels": get_allowed_ai_labels()})



@rules_bp.route("/mark-all-read", methods=["POST"])
def mark_all_read():
    """
    Mark all messages in INBOX as read.
    NOTE: This already uses batchModify elsewhere in this file (not touched in Step 1).
    """
    try:
        service = get_gmail_service_for_current_user()
    except RuntimeError as e:
        return jsonify({"error": str(e)}), 401
    except Exception as e:
        logger.exception("Gmail auth failed in mark_all_read")
        return jsonify({"error": f"Gmail auth failed: {e}"}), 500

    # List messages in INBOX
    try:
        msg_list = (
            service.users()
            .messages()
            .list(userId="me", labelIds=["INBOX"], maxResults=500)
            .execute()
        )
        messages = msg_list.get("messages", [])
    except HttpError as e:
        logger.exception("Gmail list failed in mark_all_read")
        return jsonify({"error": f"Gmail list failed: {e}"}), 500

    all_ids = [m["id"] for m in messages if m.get("id")]
    if not all_ids:
        return jsonify({"status": "ok", "updated": 0, "message": "No messages in inbox."})

    # Mark them read via batchModify
    try:
        service.users().messages().batchModify(
            userId="me",
            body={
                "ids": all_ids,
                "removeLabelIds": ["UNREAD"],
            },
        ).execute()
    except HttpError as e:
        logger.exception("Gmail batchModify failed")
        return jsonify({"error": f"Gmail batchModify failed: {e}"}), 500

    return jsonify(
        {
            "status": "ok",
            "updated": len(all_ids),
            "message": f"Marked {len(all_ids)} messages as read.",
        }
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
            lookback_days=SENDER_RULES_LOOKBACK_DAYS,
        )
        logger.info("Sender-email rule sync summary: %s", sender_sync_summary)
    except Exception:
        logger.exception("Sender-email rule sync failed; continuing with existing rules/AI.")

    # Reload rules AFTER learning, so new sender rules apply immediately in this run
    rules = load_active_rules()
    rule_count = 0
    ai_count = 0
    total = 0

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
                    remove_from_inbox=ARCHIVE_RULE_LABELED,
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
                rule_count += 1
                break

        if not matched_label:
            label, conf = ai_suggest_label(sender, subject, body)
            if label:
                apply_label_to_message(
                    service,
                    gmail_id,
                    label,
                    remove_from_inbox=ARCHIVE_AI_LABELED,
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
                record_ai_suggestion(
                    gmail_id=gmail_id,
                    suggested_label=label,
                    confidence=float(conf or 0.0),
                    reason="model",
                )
                ai_count += 1

        # loop continues

    return jsonify(
        {
            "status": "ok",
            "total_scanned": total,
            "rules_applied": rule_count,
            "ai_applied": ai_count,
            "sender_sync": sender_sync_summary,
        }
    )
