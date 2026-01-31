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


def _ms_epoch_to_iso(ms: str | None) -> str | None:
    if not ms:
        return None
    try:
        return datetime.utcfromtimestamp(int(ms) / 1000).isoformat(timespec="seconds") + "Z"
    except Exception:
        return None


def _derive_mailbox_and_category(label_ids: list[str]) -> dict:
    s = set(label_ids or [])
    in_inbox = "INBOX" in s

    # Category labels are system labels like CATEGORY_PERSONAL, CATEGORY_PROMOTIONS, etc.
    category_labels = sorted([x for x in s if x.startswith("CATEGORY_")])

    # We treat “category” as the first one if any exist
    category = category_labels[0] if category_labels else None

    return {
        "in_inbox": in_inbox,
        "category": category,
        "raw_category_labels": category_labels,
    }


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


@rules_bp.route("/init-default-labels", methods=["POST"])
def init_default_labels():
    try:
        service = get_gmail_service_for_current_user()
    except RuntimeError as e:
        return jsonify({"error": str(e)}), 401
    except Exception as e:
        logger.exception("Gmail auth failed in init_default_labels")
        return jsonify({"error": f"Gmail auth failed: {e}"}), 500

    ensured = 0
    for name in DEFAULT_LL_LABELS:
        get_or_create_gmail_label(service, name)
        ensured += 1
    return jsonify({"status": "ok", "count": ensured})


@rules_bp.route("/learn-rules", methods=["POST"])
def learn_rules():
    created = learn_rules_from_labeled_emails()
    return jsonify({"status": "ok", "created": created})


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

    def log(event: str, payload: dict):
        if not fp:
            return
        _log_line(
            fp,
            {
                "ts": _utc_ts(),
                "event": event,
                **payload,
            },
        )

    # Only look in CATEGORY_PERSONAL per your request
    gmail_query = "category:personal"

    log(
        "run_started",
        {
            "query": gmail_query,
            "max_emails": MAX_EMAILS_PER_RUN,
            "sender_sync_summary": sender_sync_summary,
            "rules_loaded": len(rules),
        },
    )

    try:
        resp = (
            service.users()
            .messages()
            .list(userId="me", q=gmail_query, maxResults=MAX_EMAILS_PER_RUN)
            .execute()
        )
    except HttpError:
        logger.exception("Gmail list failed in run_labeler")
        if fp:
            fp.close()
        return jsonify({"error": "Gmail list failed"}), 500

    messages = resp.get("messages", []) or []

    for msg in messages:
        gmail_id = msg.get("id")
        if not gmail_id:
            continue

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

        # BEFORE any action: capture labelIds, read/unread, category, received date
        before_label_ids = full.get("labelIds", []) or []
        before_is_unread = "UNREAD" in set(before_label_ids)
        mailbox_info = _derive_mailbox_and_category(before_label_ids)
        received_internal_ms = full.get("internalDate")
        received_iso_utc = _ms_epoch_to_iso(received_internal_ms)

        fields = extract_email_fields(full)
        # Support both legacy (4-tuple) and newer (6-tuple) extract_email_fields signatures
        if isinstance(fields, (list, tuple)) and len(fields) == 4:
            sender, subject, snippet, body = fields
            thread_id = full.get("threadId", "")
            internal_date = full.get("internalDate")
        elif isinstance(fields, (list, tuple)) and len(fields) == 6:
            sender, subject, body, snippet, thread_id, internal_date = fields
        else:
            raise ValueError(
                f"Unexpected extract_email_fields return value: {type(fields)} len={len(fields) if hasattr(fields, '__len__') else 'n/a'}"
            )
        thread_id = full.get("threadId", "")

        log(
            "email_loaded_before_actions",
            {
                "gmail_id": gmail_id,
                "thread_id": thread_id,
                "sender": sender,
                "subject": subject,
                "received_internalDate_ms": received_internal_ms,
                "received_utc": received_iso_utc,
                "is_unread_before": before_is_unread,
                "in_inbox_before": mailbox_info["in_inbox"],
                "category_before": mailbox_info["category"],
                "raw_category_labels_before": mailbox_info["raw_category_labels"],
                "label_ids_before": sorted(before_label_ids),
            },
        )

        # Apply rule-based labels first
        applied_by_rule = False
        for rule in rules:
            if email_matches_rule(sender, subject, body, rule):
                label_name = rule["label_name"]
                try:
                    label_id = get_or_create_gmail_label(service, label_name)

                    add_label_ids = [label_id]
                    remove_label_ids = []
                    if REMOVE_FROM_INBOX_ON_LABEL:
                        remove_label_ids.append("INBOX")
                    if rule.get("mark_as_read"):
                        remove_label_ids.append("UNREAD")

                    apply_label_to_message(
                        service,
                        gmail_id,
                        add_label_ids=add_label_ids,
                        remove_label_ids=remove_label_ids,
                    )

                    record_labeled_email(
                        gmail_id=gmail_id,
                        thread_id=thread_id,
                        label=label_name,
                        method="rule",
                        sender=sender,
                        subject=subject,
                    )

                    rule_count += 1
                    applied_by_rule = True

                    log(
                        "rule_applied",
                        {
                            "gmail_id": gmail_id,
                            "thread_id": thread_id,
                            "label": label_name,
                            "mark_as_read": bool(rule.get("mark_as_read")),
                            "remove_from_inbox": bool(REMOVE_FROM_INBOX_ON_LABEL),
                        },
                    )

                    if ARCHIVE_RULE_LABELED:
                        # optional: archive means remove INBOX
                        try:
                            apply_label_to_message(
                                service,
                                gmail_id,
                                add_label_ids=[],
                                remove_label_ids=["INBOX"],
                            )
                            log(
                                "rule_archived",
                                {"gmail_id": gmail_id, "thread_id": thread_id, "archived": True},
                            )
                        except Exception:
                            logger.exception("Archiving failed (rule)")

                except Exception:
                    logger.exception("Rule apply failed")
                    log(
                        "rule_apply_failed",
                        {"gmail_id": gmail_id, "thread_id": thread_id, "label": label_name},
                    )

                break

        if applied_by_rule:
            continue

        # AI suggestion if no rule matched
        try:
            allowed_labels = get_allowed_ai_labels()
            suggested_label = ai_suggest_label(sender, subject, snippet, allowed_labels=allowed_labels)
        except Exception:
            logger.exception("AI suggest failed")
            log("ai_suggest_failed", {"gmail_id": gmail_id, "thread_id": thread_id})
            continue

        if not suggested_label:
            log("ai_no_suggestion", {"gmail_id": gmail_id, "thread_id": thread_id})
            continue

        try:
            label_id = get_or_create_gmail_label(service, suggested_label)

            add_label_ids = [label_id]
            remove_label_ids = []
            if REMOVE_FROM_INBOX_ON_LABEL:
                remove_label_ids.append("INBOX")

            apply_label_to_message(
                service,
                gmail_id,
                add_label_ids=add_label_ids,
                remove_label_ids=remove_label_ids,
            )

            record_ai_suggestion(
                gmail_id=gmail_id,
                thread_id=thread_id,
                label=suggested_label,
                sender=sender,
                subject=subject,
                snippet=snippet,
            )
            record_labeled_email(
                gmail_id=gmail_id,
                thread_id=thread_id,
                label=suggested_label,
                method="ai",
                sender=sender,
                subject=subject,
            )

            ai_count += 1
            log(
                "ai_applied",
                {"gmail_id": gmail_id, "thread_id": thread_id, "label": suggested_label},
            )

            if ARCHIVE_AI_LABELED:
                try:
                    apply_label_to_message(
                        service,
                        gmail_id,
                        add_label_ids=[],
                        remove_label_ids=["INBOX"],
                    )
                    log("ai_archived", {"gmail_id": gmail_id, "thread_id": thread_id, "archived": True})
                except Exception:
                    logger.exception("Archiving failed (ai)")

        except Exception:
            logger.exception("AI apply failed")
            log("ai_apply_failed", {"gmail_id": gmail_id, "thread_id": thread_id, "label": suggested_label})

    log(
        "run_finished",
        {
            "total_processed": total,
            "rule_applied": rule_count,
            "ai_applied": ai_count,
            "log_path": log_path,
        },
    )

    if fp:
        fp.close()

    return jsonify(
        {
            "status": "ok",
            "total": total,
            "rule_applied": rule_count,
            "ai_applied": ai_count,
            "sender_sync_summary": sender_sync_summary,
            "download_log_url": "/download-run-log",
        }
    )
