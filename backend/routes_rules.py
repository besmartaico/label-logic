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


def validate_rule_label_name(label_name: str):
    from gmail_client import is_probably_valid_label_name

    if not label_name:
        return False, "label_name is required"
    if not is_probably_valid_label_name(label_name):
        return False, "Label name is empty, too long, or otherwise invalid."
    return True, None


def email_matches_rule(sender, subject, body, rule):
    s_from = (sender or "").lower()
    s_subject = (subject or "").lower()
    s_body = (body or "").lower()

    from_term = (rule["from_contains"] or "").lower().strip()
    subj_term = (rule["subject_contains"] or "").lower().strip()
    body_term = (rule["body_contains"] or "").lower().strip()

    if from_term and from_term in s_from:
        return True
    if subj_term and subj_term in s_subject:
        return True
    if body_term and body_term in s_body:
        return True

    return False


# -----------------------------
# Routes
# -----------------------------


@rules_bp.route("/rules", methods=["GET"])
def rules_page():
    from flask import session, redirect, url_for

    if "google_user_id" not in session:
        return redirect(url_for("misc.auth_google"))
    return render_template("rules.html")


@rules_bp.route("/api/rules", methods=["GET"])
def api_get_rules():
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("SELECT * FROM rules ORDER BY id;")
    rows = cur.fetchall()
    conn.close()

    rules = [db_row_to_rule(r) for r in rows]
    return jsonify(rules)


@rules_bp.route("/api/rules", methods=["POST"])
def api_create_rule():
    data = request.get_json() or {}
    label_name = (data.get("label_name") or "").strip()
    from_contains = (data.get("from_contains") or "").strip()
    subject_contains = (data.get("subject_contains") or "").strip()
    body_contains = (data.get("body_contains") or "").strip()
    is_active = bool(data.get("is_active", True))
    mark_as_read = bool(data.get("mark_as_read", False))

    is_valid, error_msg = validate_rule_label_name(label_name)
    if not is_valid:
        return jsonify({"error": error_msg}), 400

    now = datetime.utcnow().isoformat(timespec="seconds")

    conn = get_db_connection()
    cur = conn.cursor()
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
            from_contains,
            subject_contains,
            body_contains,
            is_active,
            mark_as_read,
            now,
            now,
        ),
    )
    new_row = cur.fetchone()
    new_id = new_row["id"]
    conn.commit()
    conn.close()

    return (
        jsonify(
            {
                "id": new_id,
                "label_name": label_name,
                "from_contains": from_contains,
                "subject_contains": subject_contains,
                "body_contains": body_contains,
                "is_active": bool(is_active),
                "mark_as_read": bool(mark_as_read),
            }
        ),
        201,
    )


@rules_bp.route("/api/rules/<int:rule_id>", methods=["PUT"])
def api_update_rule(rule_id):
    data = request.get_json() or {}
    label_name = data.get("label_name")
    from_contains = data.get("from_contains")
    subject_contains = data.get("subject_contains")
    body_contains = data.get("body_contains")
    is_active = data.get("is_active")
    mark_as_read = data.get("mark_as_read")

    conn = get_db_connection()
    cur = conn.cursor()

    cur.execute("SELECT * FROM rules WHERE id = %s;", (rule_id,))
    row = cur.fetchone()
    if not row:
        conn.close()
        return jsonify({"error": "Rule not found"}), 404

    new_label_name = (label_name or row["label_name"]).strip()
    new_from = (
        (from_contains if from_contains is not None else row.get("from_contains") or "")
        .strip()
    )
    new_subject = (
        (subject_contains if subject_contains is not None else row.get("subject_contains") or "")
        .strip()
    )
    new_body = (
        (body_contains if body_contains is not None else row.get("body_contains") or "")
        .strip()
    )
    new_is_active = bool(is_active if is_active is not None else row.get("is_active"))
    new_mark_as_read = bool(
        mark_as_read if mark_as_read is not None else row.get("mark_as_read")
    )

    is_valid, error_msg = validate_rule_label_name(new_label_name)
    if not is_valid:
        conn.close()
        return jsonify({"error": error_msg}), 400

    now = datetime.utcnow().isoformat(timespec="seconds")

    cur.execute(
        """
        UPDATE rules
        SET label_name = %s,
            from_contains = %s,
            subject_contains = %s,
            body_contains = %s,
            is_active = %s,
            mark_as_read = %s,
            updated_at = %s
        WHERE id = %s;
        """,
        (
            new_label_name,
            new_from,
            new_subject,
            new_body,
            new_is_active,
            new_mark_as_read,
            now,
            rule_id,
        ),
    )
    conn.commit()
    conn.close()

    return jsonify(
        {
            "id": rule_id,
            "label_name": new_label_name,
            "from_contains": new_from,
            "subject_contains": new_subject,
            "body_contains": new_body,
            "is_active": bool(new_is_active),
            "mark_as_read": bool(new_mark_as_read),
        }
    )


@rules_bp.route("/api/rules/<int:rule_id>", methods=["DELETE"])
def api_delete_rule(rule_id):
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("DELETE FROM rules WHERE id = %s;", (rule_id,))
    conn.commit()
    conn.close()
    return jsonify({"status": "deleted"})


@rules_bp.route("/api/gmail-labels", methods=["GET"])
def api_gmail_labels():
    try:
        service = get_gmail_service_for_current_user()
    except RuntimeError as e:
        return jsonify({"error": str(e)}), 401
    except Exception as e:
        logger.exception("Gmail auth failed when fetching Gmail labels")
        return jsonify({"error": f"Gmail auth failed: {e}"}), 500

    try:
        resp = service.users().labels().list(userId="me").execute()
        labels = resp.get("labels", [])
    except HttpError as e:
        logger.exception("Gmail labels list failed")
        return jsonify({"error": f"Gmail labels list failed: {e}"}), 500

    user_labels = [
        {"id": lbl["id"], "name": lbl.get("name", "")}
        for lbl in labels
        if lbl.get("type") == "user"
    ]
    return jsonify(user_labels)


@rules_bp.route("/api/labels", methods=["GET"])
def api_get_labels():
    try:
        service = get_gmail_service_for_current_user()
    except RuntimeError as e:
        return jsonify({"error": str(e)}), 401
    except Exception as e:
        logger.exception("Gmail auth failed when fetching labels")
        return jsonify({"error": f"Gmail auth failed: {e}"}), 500

    try:
        resp = service.users().labels().list(userId="me").execute()
        labels = resp.get("labels", [])
    except HttpError as e:
        logger.exception("Gmail labels list failed")
        return jsonify({"error": f"Gmail labels list failed: {e}"}), 500

    excluded_ids = {"CHAT", "SENT", "TRASH", "DRAFT", "SPAM", "STARRED"}

    enriched = []
    for lbl in labels:
        try:
            detail = service.users().labels().get(userId="me", id=lbl["id"]).execute()
        except HttpError:
            logger.exception("Error fetching label detail for %s", lbl.get("name"))
            continue

        lid = detail.get("id", "")
        if lid in excluded_ids or lid.startswith("CATEGORY_"):
            continue

        enriched.append(
            {
                "id": detail["id"],
                "name": detail.get("name", ""),
                "type": detail.get("type", ""),
                "messagesUnread": detail.get("messagesUnread", 0),
                "messagesTotal": detail.get("messagesTotal", 0),
            }
        )

    return jsonify(enriched)


@rules_bp.route("/api/labels/<label_id>/mark-read", methods=["POST"])
def api_mark_label_read(label_id):
    try:
        service = get_gmail_service_for_current_user()
    except RuntimeError as e:
        return jsonify({"error": str(e)}), 401
    except Exception as e:
        logger.exception("Gmail auth failed when marking label read")
        return jsonify({"error": f"Gmail auth failed: {e}"}), 500

    user_id = "me"
    all_ids = []
    page_token = None

    try:
        while True:
            resp = (
                service.users()
                .messages()
                .list(
                    userId=user_id,
                    labelIds=[label_id, "UNREAD"],
                    pageToken=page_token,
                    maxResults=500,
                )
                .execute()
            )

            messages = resp.get("messages", [])
            all_ids.extend(m["id"] for m in messages)

            page_token = resp.get("nextPageToken")
            if not page_token:
                break
    except HttpError:
        logger.exception("Gmail list failed when marking label read")
        return jsonify({"error": "Gmail list failed"}), 500

    if not all_ids:
        return jsonify(
            {"status": "ok", "updated": 0, "message": "No unread messages in this label."}
        )

    CHUNK_SIZE = 1000
    try:
        for i in range(0, len(all_ids), CHUNK_SIZE):
            chunk = all_ids[i : i + CHUNK_SIZE]
            service.users().messages().batchModify(
                userId=user_id,
                body={"ids": chunk, "removeLabelIds": ["UNREAD"]},
            ).execute()
    except HttpError:
        logger.exception("Gmail batchModify failed when marking label read")
        return jsonify({"error": "Gmail batchModify failed"}), 500

    return jsonify(
        {"status": "ok", "updated": len(all_ids), "message": f"Marked {len(all_ids)} messages as read."}
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
                record_ai_suggestion(gmail_id, label, conf)
                ai_count += 1

    logger.info(
        "run_labeler finished: processed=%d rule_labeled=%d ai_labeled=%d",
        total,
        rule_count,
        ai_count,
    )

    return jsonify(
        {"status": "ok", "processed": total, "rule_labeled": rule_count, "ai_labeled": ai_count}
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
        if label_id:
            ensured.append({"name": name, "id": label_id})

    return jsonify({"status": "ok", "count": len(ensured), "ensured_labels": ensured})
