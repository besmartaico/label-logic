import os
import json
import logging
from datetime import datetime, timezone

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

# If true, only process UNREAD Inbox messages in /run-labeler
PROCESS_UNREAD_ONLY = os.environ.get("PROCESS_UNREAD_ONLY", "true").lower() in (
    "1",
    "true",
    "yes",
    "on",
)

# sender-email learning config
LL_LABEL_PREFIX = os.environ.get("LL_LABEL_PREFIX", "@LL-")
try:
    SENDER_RULES_MAX_PER_LABEL = int(os.environ.get("SENDER_RULES_MAX_PER_LABEL", "200"))
    if SENDER_RULES_MAX_PER_LABEL <= 0:
        SENDER_RULES_MAX_PER_LABEL = 200
except ValueError:
    SENDER_RULES_MAX_PER_LABEL = 200

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


def _ms_epoch_to_iso(ms: str | int | None) -> str | None:
    """
    Gmail internalDate is milliseconds since epoch (string).
    Return ISO 8601 (UTC) like 2026-01-31T01:22:00Z.
    """
    if ms is None:
        return None
    try:
        ms_int = int(ms)
        dt = datetime.fromtimestamp(ms_int / 1000, tz=timezone.utc)
        return dt.isoformat().replace("+00:00", "Z")
    except Exception:
        return None


def _derive_mailbox_and_category(label_ids: list[str]) -> dict:
    """
    "Mailbox" here means high-level placement and category signals we can infer.
    - in_inbox: bool
    - category: Primary/Promotions/Social/Updates/Forums (best-effort)
    - raw_category_labels: list of CATEGORY_* labels
    """
    s = set(label_ids or [])

    in_inbox = "INBOX" in s

    # Category labels Gmail may apply
    category_map = {
        "CATEGORY_PERSONAL": "Primary",
        "CATEGORY_PROMOTIONS": "Promotions",
        "CATEGORY_SOCIAL": "Social",
        "CATEGORY_UPDATES": "Updates",
        "CATEGORY_FORUMS": "Forums",
    }
    raw_category_labels = [lid for lid in s if lid.startswith("CATEGORY_")]

    # Prefer explicit category labels
    category = None
    for lid, name in category_map.items():
        if lid in s:
            category = name
            break

    # If it's in inbox but we can't see a category label, call it "Inbox (uncategorized)"
    if in_inbox and not category:
        category = "Inbox (uncategorized)"

    return {
        "in_inbox": in_inbox,
        "category": category,
        "raw_category_labels": sorted(raw_category_labels),
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
        {
            "status": "ok",
            "updated": len(all_ids),
            "message": f"Marked {len(all_ids)} messages as read.",
        }
    )


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

    # Step 0: Learn sender-email rules from ANY @LL-* labels (latest wins)
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
                "process_unread_only_env": PROCESS_UNREAD_ONLY,
                "remove_from_inbox_on_label": REMOVE_FROM_INBOX_ON_LABEL,
                "archive_rule_labeled_env": ARCHIVE_RULE_LABELED,
                "archive_ai_labeled_env": ARCHIVE_AI_LABELED,
            },
        )

    # Only include UNREAD when PROCESS_UNREAD_ONLY=true
    label_ids = ["INBOX"]
    if PROCESS_UNREAD_ONLY:
        label_ids.append("UNREAD")

    try:
        msg_list = (
            service.users()
            .messages()
            .list(userId="me", labelIds=label_ids, maxResults=MAX_EMAILS_PER_RUN)
            .execute()
        )
        messages = msg_list.get("messages", [])
    except HttpError as e:
        logger.exception("Gmail list failed in run_labeler")
        return jsonify({"error": f"Gmail list failed: {e}"}), 500

    if fp:
        _log_line(
            fp,
            {
                "ts": _utc_ts(),
                "event": "fetched_messages",
                "count": len(messages),
                "label_filter": label_ids,
            },
        )

    for m in messages:
        gmail_id = m["id"]
        total += 1

        # Pull message metadata + content
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

        sender, subject, snippet, body = extract_email_fields(full)
        thread_id = full.get("threadId", "")

        if fp:
            _log_line(
                fp,
                {
                    "ts": _utc_ts(),
                    "event": "email_loaded_before_actions",
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

        matched_label = None
        matched_rule_mark_read = False
        matched_rule_id = None

        # RULE PASS
        for rule in rules:
            if email_matches_rule(sender, subject, body, rule):
                matched_label = rule["label_name"]
                matched_rule_mark_read = rule.get("mark_as_read", False)
                matched_rule_id = rule.get("id")

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
                            "event": "action_taken",
                            "gmail_id": gmail_id,
                            "thread_id": thread_id,
                            "method": "rule",
                            "rule_id": matched_rule_id,
                            "applied_label": matched_label,
                            "remove_from_inbox": REMOVE_FROM_INBOX_ON_LABEL,
                            "mark_as_read": bool(matched_rule_mark_read),
                        },
                    )

                rule_count += 1
                break

        # AI PASS
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
                            "event": "action_taken",
                            "gmail_id": gmail_id,
                            "thread_id": thread_id,
                            "method": "ai",
                            "confidence": conf,
                            "applied_label": label,
                            "remove_from_inbox": REMOVE_FROM_INBOX_ON_LABEL,
                            "mark_as_read": False,
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
