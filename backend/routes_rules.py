import os
import json
import logging
from datetime import datetime, timezone

try:
    # Python 3.9+
    from zoneinfo import ZoneInfo
except Exception:  # pragma: no cover
    ZoneInfo = None

from flask import Blueprint, render_template, jsonify, request, send_file, session
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

def _migrate_rules_table():
    """Add new columns to rules table if missing, and backfill existing rows."""
    conn = get_db_connection()
    cur = conn.cursor()
    try:
        # Add each column individually — ignore error if it already exists
        for ddl in [
            "ALTER TABLE rules ADD COLUMN keep_in_inbox BOOLEAN NOT NULL DEFAULT FALSE",
            "ALTER TABLE rules ADD COLUMN star_email BOOLEAN NOT NULL DEFAULT FALSE",
            "ALTER TABLE rules ADD COLUMN google_user_id TEXT",
        ]:
            try:
                cur.execute(ddl)
                conn.commit()
            except Exception:
                conn.rollback()  # column already exists — that's fine
        # Add created_by column
        try:
            cur.execute("ALTER TABLE rules ADD COLUMN created_by TEXT NOT NULL DEFAULT 'user'")
            conn.commit()
        except Exception:
            conn.rollback()
        # Delete single-word subject-only rules (too broad — e.g. "men", "sale")
        try:
            cur.execute("""
                DELETE FROM rules
                WHERE subject_contains IS NOT NULL
                  AND subject_contains != ''
                  AND TRIM(subject_contains) NOT LIKE '% %'
                  AND TRIM(subject_contains) NOT LIKE '%@%'
                  AND TRIM(subject_contains) NOT LIKE '%.%'
                  AND (from_contains IS NULL OR from_contains = '')
                  AND (body_contains IS NULL OR body_contains = '')
            """)
            conn.commit()
        except Exception:
            conn.rollback()
        # Add user_settings table for per-user preferences
        try:
            cur.execute("""
                CREATE TABLE IF NOT EXISTS user_settings (
                    google_user_id TEXT PRIMARY KEY,
                    ai_instructions TEXT,
                    schedule_config TEXT,
                    updated_at TEXT
                )
            """)
            conn.commit()
        except Exception:
            conn.rollback()
        # Add schedule_runs table to persist scheduled run history
        try:
            cur.execute("""
                CREATE TABLE IF NOT EXISTS schedule_runs (
                    id BIGSERIAL PRIMARY KEY,
                    google_user_id TEXT,
                    run_type TEXT,
                    processed INTEGER DEFAULT 0,
                    rule_labeled INTEGER DEFAULT 0,
                    ai_labeled INTEGER DEFAULT 0,
                    skipped INTEGER DEFAULT 0,
                    rules_created INTEGER DEFAULT 0,
                    ran_at TEXT,
                    created_at TEXT
                )
            """)
            conn.commit()
        except Exception:
            conn.rollback()
        # Add schedule_config column if missing
        try:
            cur.execute("ALTER TABLE user_settings ADD COLUMN schedule_config TEXT")
            conn.commit()
        except Exception:
            conn.rollback()
        # Delete subject-only rules created by AI or learned (from addresses only from now on)
        try:
            cur.execute("""
                DELETE FROM rules
                WHERE (created_by IN ('ai', 'learned') OR created_by IS NULL)
                  AND (from_contains IS NULL OR from_contains = '')
                  AND (subject_contains IS NOT NULL AND subject_contains != '')
            """)
            conn.commit()
        except Exception:
            conn.rollback()
        # Backfill all existing NULL-owner rules to jefferyweeks@gmail.com
        cur.execute("""
            UPDATE rules
            SET google_user_id = (
                SELECT google_user_id FROM google_accounts
                WHERE email = 'jefferyweeks@gmail.com'
                LIMIT 1
            )
            WHERE google_user_id IS NULL
        """)
        conn.commit()
        logger.info("_migrate_rules_table complete")
    except Exception:
        logger.exception("_migrate_rules_table failed")
    finally:
        conn.close()

_migrate_rules_table()

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

# Restrict processing to Primary tab only (Gmail CATEGORY_PERSONAL)
PROCESS_PRIMARY_ONLY = os.environ.get("PROCESS_PRIMARY_ONLY", "true").lower() in (
    "1",
    "true",
    "yes",
    "on",
)

# ✅ NEW: only process UNREAD messages
PROCESS_UNREAD_ONLY = os.environ.get("PROCESS_UNREAD_ONLY", "true").lower() in (
    "1",
    "true",
    "yes",
    "on",
)

# Sender-email learning config
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

    # Prefer the app/user timezone for readability. Default to America/Denver (Mountain).
    tzname = os.environ.get("APP_TIMEZONE", "America/Denver")
    if ZoneInfo is not None:
        try:
            dt_local = dt_utc.astimezone(ZoneInfo(tzname))
        except Exception:
            dt_local = dt_utc
    else:
        dt_local = dt_utc

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
        "keep_in_inbox": bool(row.get("keep_in_inbox")),
        "star_email": bool(row.get("star_email")),
        "google_user_id": row.get("google_user_id"),
        "created_by": row.get("created_by") or "user",
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

@rules_bp.route("/labels", methods=["GET"])
def labels_page():
    return render_template("labels.html")

@rules_bp.route("/rule-editor", methods=["GET"])
def rule_editor_page():
    return render_template("rule-editor.html")

@rules_bp.route("/rule-list", methods=["GET"])
def rule_list_page():
    return render_template("rule-list.html")


@rules_bp.route("/api/debug-session", methods=["GET"])
def api_debug_session():
    """Temporary debug endpoint to diagnose auth issues."""
    user_id = session.get("google_user_id")
    email = session.get("email", "")
    conn = get_db_connection()
    cur = conn.cursor()
    # Check google_accounts rows
    cur.execute("SELECT google_user_id, email, CASE WHEN credentials_json IS NULL THEN 'NULL' WHEN credentials_json = '' THEN 'EMPTY' ELSE 'HAS_CREDS' END as creds_status FROM google_accounts ORDER BY updated_at DESC LIMIT 10")
    accounts = [dict(r) for r in cur.fetchall()]
    conn.close()
    return jsonify({
        "session_user_id": user_id,
        "session_email": email,
        "google_accounts": accounts,
    })

@rules_bp.route("/api/allowed-ai-labels", methods=["GET"])
def api_allowed_ai_labels():
    return jsonify({"allowed_ai_labels": get_allowed_ai_labels()})


@rules_bp.route("/api/rules", methods=["GET"])
def api_get_rules():
    user_id = session.get("google_user_id")
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("SELECT * FROM rules WHERE google_user_id = %s ORDER BY id;", (user_id,))
    rows = cur.fetchall()
    conn.close()
    return jsonify([db_row_to_rule(r) for r in rows])


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
    user_id = session.get("google_user_id")
    cur.execute("DELETE FROM rules WHERE id = %s AND google_user_id = %s;", (rule_id, user_id))
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
        return jsonify({"status": "ok", "updated": 0, "message": "No unread messages in this label."})

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

    return jsonify({"status": "ok", "updated": len(all_ids), "message": f"Marked {len(all_ids)} messages as read."})


@rules_bp.route("/download-run-log", methods=["GET"])
def download_run_log():
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

    run_user_id = session.get("google_user_id")
    # Load this user's AI instructions
    try:
        _conn_ai = get_db_connection()
        _cur_ai = _conn_ai.cursor()
        _cur_ai.execute("SELECT ai_instructions FROM user_settings WHERE google_user_id = %s", (run_user_id,))
        _ai_row = _cur_ai.fetchone()
        raw_instructions = _ai_row["ai_instructions"] if _ai_row else None
        if raw_instructions:
            try:
                items = json.loads(raw_instructions)
                if isinstance(items, list):
                    _run_ai_instructions = "\n".join(item["text"] for item in items if item.get("text"))
                else:
                    _run_ai_instructions = str(raw_instructions)
            except Exception:
                _run_ai_instructions = str(raw_instructions)
        else:
            _run_ai_instructions = ""
        _conn_ai.close()
    except Exception:
        _run_ai_instructions = ""
    conn_r = get_db_connection()
    cur_r = conn_r.cursor()
    cur_r.execute("SELECT * FROM rules WHERE is_active = TRUE AND google_user_id = %s ORDER BY id;", (run_user_id,))
    rules = [db_row_to_rule(r) for r in cur_r.fetchall()]
    conn_r.close()
    rule_count = 0
    ai_count = 0
    total = 0

    log_path = _run_log_path()
    try:
        fp = open(log_path, "w", encoding="utf-8")
    except Exception:
        fp = None
        logger.exception("Failed to open run log at %s", log_path)

    # ✅ Build Gmail label filter
    # Primary-only: INBOX + CATEGORY_PERSONAL
    # Unread-only: add UNREAD
    label_filter = ["INBOX"]
    if PROCESS_PRIMARY_ONLY:
        label_filter.append("CATEGORY_PERSONAL")
    if PROCESS_UNREAD_ONLY:
        label_filter.append("UNREAD")

    if fp:
        _log_line(
            fp,
            {
                "ts": _utc_ts(),
                "event": "run_start",
                "max_emails_per_run": MAX_EMAILS_PER_RUN,
                "process_primary_only": PROCESS_PRIMARY_ONLY,
                "process_unread_only": PROCESS_UNREAD_ONLY,
                "gmail_label_filter": label_filter,
                "remove_from_inbox_on_label": REMOVE_FROM_INBOX_ON_LABEL,
                "archive_rule_labeled_env": ARCHIVE_RULE_LABELED,
                "archive_ai_labeled_env": ARCHIVE_AI_LABELED,
            },
        )

    try:
        msg_list = (
            service.users()
            .messages()
            .list(userId="me", labelIds=label_filter, maxResults=MAX_EMAILS_PER_RUN)
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

        pre_label_ids = full.get("labelIds", []) or []
        pre_categories = _extract_gmail_categories(pre_label_ids)
        received_at = _human_received_at(full)

        # Skip emails that already have a user-applied label (not a system label).
        # Gmail user-created label IDs always start with "Label_" followed by digits.
        # All built-in Gmail system labels are plain uppercase words or CATEGORY_* prefixed.
        GMAIL_SYSTEM_LABELS = {
            "INBOX", "UNREAD", "STARRED", "IMPORTANT", "SENT", "DRAFT",
            "SPAM", "TRASH", "CHAT", "CATEGORY_PERSONAL", "CATEGORY_SOCIAL",
            "CATEGORY_PROMOTIONS", "CATEGORY_UPDATES", "CATEGORY_FORUMS",
        }
        already_user_labeled = any(
            lid.startswith("Label_")
            for lid in pre_label_ids
        )
        if already_user_labeled:
            if fp:
                _log_line(fp, {
                    "ts": _utc_ts(), "event": "skipped_already_labeled",
                    "gmail_id": gmail_id, "sender": sender, "subject": subject,
                    "label_ids": pre_label_ids,
                })
            continue

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
            # NOTE: this is still one AI request per email (we’ll batch next step)
            label, conf = ai_suggest_label(sender, subject, body, extra_instructions=_run_ai_instructions)
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
        if label_id:
            ensured.append({"name": name, "id": label_id})

    return jsonify({"status": "ok", "count": len(ensured), "ensured_labels": ensured})


@rules_bp.route("/api/ai-instructions", methods=["GET"])
def api_get_ai_instructions():
    user_id = session.get("google_user_id")
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("SELECT ai_instructions FROM user_settings WHERE google_user_id = %s", (user_id,))
    row = cur.fetchone()
    conn.close()
    raw = row["ai_instructions"] if row else None
    # Support both old plain text and new JSON list format
    if raw:
        try:
            items = json.loads(raw)
            if not isinstance(items, list):
                items = [{"id": 1, "text": raw}]
        except Exception:
            items = [{"id": 1, "text": raw}]
    else:
        items = []
    return jsonify({"items": items})

@rules_bp.route("/api/ai-instructions", methods=["POST"])
def api_save_ai_instructions():
    user_id = session.get("google_user_id")
    data = request.get_json(force=True, silent=True) or {}
    # Expects {"items": [{"id": ..., "text": "..."}]}
    items = data.get("items", [])
    if not isinstance(items, list):
        items = []
    now = datetime.utcnow().isoformat(timespec="seconds")
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("""
        INSERT INTO user_settings (google_user_id, ai_instructions, updated_at)
        VALUES (%s, %s, %s)
        ON CONFLICT (google_user_id) DO UPDATE
        SET ai_instructions = EXCLUDED.ai_instructions, updated_at = EXCLUDED.updated_at
    """, (user_id, json.dumps(items), now))
    conn.commit()
    conn.close()
    return jsonify({"status": "ok"})

@rules_bp.route("/api/schedule-runs", methods=["GET"])
def api_get_schedule_runs():
    user_id = session.get("google_user_id")
    conn = get_db_connection()
    cur = conn.cursor()
    # Get last run for each type
    cur.execute("""
        SELECT DISTINCT ON (run_type) run_type, processed, rule_labeled, ai_labeled,
               skipped, rules_created, ran_at
        FROM schedule_runs
        WHERE google_user_id = %s
        ORDER BY run_type, ran_at DESC
    """, (user_id,))
    rows = cur.fetchall()
    conn.close()
    result = {}
    for r in rows:
        result[r['run_type']] = dict(r)
    return jsonify(result)

@rules_bp.route("/api/schedule-runs", methods=["POST"])
def api_save_schedule_run():
    user_id = session.get("google_user_id")
    data = request.get_json(force=True, silent=True) or {}
    now = datetime.utcnow().isoformat(timespec="seconds")
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("""
        INSERT INTO schedule_runs
            (google_user_id, run_type, processed, rule_labeled, ai_labeled,
             skipped, rules_created, ran_at, created_at)
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
    """, (
        user_id,
        data.get('run_type', 'run_labeler'),
        data.get('processed', 0),
        data.get('rule_labeled', 0),
        data.get('ai_labeled', 0),
        data.get('skipped', 0),
        data.get('rules_created', 0),
        now,
        now,
    ))
    conn.commit()
    conn.close()
    return jsonify({"status": "ok"})

@rules_bp.route("/api/schedule", methods=["GET"])
def api_get_schedule():
    user_id = session.get("google_user_id")
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("SELECT schedule_config FROM user_settings WHERE google_user_id = %s", (user_id,))
    row = cur.fetchone()
    conn.close()
    raw = row["schedule_config"] if row else None
    default = {"run_labeler": {"enabled": False, "interval_minutes": 60},
               "learn_rules": {"enabled": False, "interval_minutes": 1440}}
    if raw:
        try:
            cfg = json.loads(raw)
        except Exception:
            cfg = default
    else:
        cfg = default
    return jsonify(cfg)

@rules_bp.route("/api/schedule", methods=["POST"])
def api_save_schedule():
    user_id = session.get("google_user_id")
    data = request.get_json(force=True, silent=True) or {}
    now = datetime.utcnow().isoformat(timespec="seconds")
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("""
        INSERT INTO user_settings (google_user_id, schedule_config, updated_at)
        VALUES (%s, %s, %s)
        ON CONFLICT (google_user_id) DO UPDATE
        SET schedule_config = EXCLUDED.schedule_config, updated_at = EXCLUDED.updated_at
    """, (user_id, json.dumps(data), now))
    conn.commit()
    conn.close()
    return jsonify({"status": "ok"})

@rules_bp.route("/schedule", methods=["GET"])
def schedule_page():
    return render_template("schedule.html")

@rules_bp.route("/learn-rules", methods=["POST"])
def learn_rules():
    try:
        service = get_gmail_service_for_current_user()
    except RuntimeError as e:
        return jsonify({"error": str(e)}), 401
    except Exception as e:
        logger.exception("Gmail auth failed in learn_rules")
        return jsonify({"error": f"Gmail auth failed: {e}"}), 500
    try:
        user_id_for_learn = session.get("google_user_id")
        allowed = get_allowed_ai_labels()
        created = learn_rules_from_labeled_emails(
            service=service,
            allowed_labels=allowed,
            max_per_label=100,
            min_domain_count=2,
            min_subject_token_count=3,
            google_user_id=user_id_for_learn,
        )
        return jsonify({"status": "ok", "created": created})
    except Exception:
        logger.exception("learn_rules failed")
        return jsonify({"error": "learn_rules failed"}), 500
