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
from ai_labels import (
    DEFAULT_LL_LABELS,
    get_allowed_ai_labels,
    ai_suggest_label,
    ai_suggest_labels_bulk,
)
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
    return render_template(
        "rules.html",
        rules=rules,
        default_ll_labels=DEFAULT_LL_LABELS,
        allowed_labels=get_allowed_ai_labels(),
    )


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
    return jsonify({"default_labels": DEFAULT_LL_LABELS, "allowed_labels": get_allowed_ai_labels()})


@rules_bp.route("/run-labeler", methods=["POST"])
def run_labeler():
    try:
        service = get_gmail_service_for_current_user()
    except RuntimeError as e:
        return jsonify({"error": str(e)}), 401
    except Exception as e:
        logger.exception("Gmail auth failed in run_labeler")
        return jsonify({"error": f"Gmail auth failed: {e}"}), 500

    # Learn sender-email rules from ANY @LL-* labels (latest wins)
    sender_sync_summary = {"status": "skipped", "created_or_updated": 0}
    try:
        sender_sync_summary = sync_sender_email_rules_from_ll_labels(
            service,
            label_prefix=LL_LABEL_PREFIX,
            max_per_label=SENDER_RULES_MAX_PER_LABEL,
            skip_free_email_domains=SENDER_RULES_SKIP_FREE_DOMAINS,
        )
        logger.info("Sender-email rule sync summary: %s", sender_sync_summary)
    except Exception:
        logger.exception("Sender-email rule sync failed; continuing with existing rules/AI.")

    # Reload rules AFTER learning
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

    # Collect unmatched emails to send to the AI in ONE bulk request.
    ai_candidates = []  # list of dicts: {id, sender, subject, body}
    ai_context = {}  # gmail_id -> {thread_id, sender, subject, snippet}

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
            ai_candidates.append({"id": gmail_id, "sender": sender, "subject": subject, "body": body})
            ai_context[gmail_id] = {
                "thread_id": thread_id,
                "sender": sender,
                "subject": subject,
                "snippet": snippet,
            }

    # --- Bulk AI classification (single OpenAI call) ---
    ai_suggestions = {}
    if ai_candidates:
        ai_suggestions = ai_suggest_labels_bulk(ai_candidates)

        # If bulk failed (e.g., parsing), fall back to a small number of single calls
        if not ai_suggestions:
            try:
                max_fallback = int(os.environ.get("MAX_AI_FALLBACK_SINGLE_CALLS", "5"))
            except ValueError:
                max_fallback = 5
            max_fallback = max(0, min(max_fallback, 10))

            logger.warning("Bulk AI returned no results; falling back to up to %d single calls", max_fallback)
            for it in ai_candidates[:max_fallback]:
                gid = it["id"]
                label, conf = ai_suggest_label(it.get("sender"), it.get("subject"), it.get("body"))
                ai_suggestions[gid] = (label, conf)

    # Apply AI suggestions
    for gmail_id, (label, conf) in (ai_suggestions or {}).items():
        if not label:
            continue

        ctx = ai_context.get(gmail_id) or {}
        thread_id = ctx.get("thread_id", "")
        sender = ctx.get("sender", "")
        subject = ctx.get("subject", "")
        snippet = ctx.get("snippet", "")

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
        {
            "status": "ok",
            "processed": total,
            "rule_labeled": rule_count,
            "ai_labeled": ai_count,
            "sender_rule_sync": sender_sync_summary,
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
        if label_id:
            ensured.append({"name": name, "id": label_id})

    return jsonify({"status": "ok", "count": len(ensured), "ensured_labels": ensured})
