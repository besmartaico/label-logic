import os
import json
import logging
from datetime import datetime, timezone

from flask import Blueprint, render_template, jsonify, request, send_file, redirect, url_for
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

# -------------------------------------------------------------------
# Source filtering for /run-labeler
# -------------------------------------------------------------------
# Default to CATEGORY_PERSONAL (Primary tab)
SOURCE_CATEGORY_LABEL = (
    os.environ.get("SOURCE_CATEGORY_LABEL", "CATEGORY_PERSONAL").strip() or "CATEGORY_PERSONAL"
)

# If true, also require the message to still be in INBOX.
# NOTE: Gmail "Category" unread counts can include messages that are no longer in INBOX.
# Keeping INBOX in the filter can dramatically reduce the number of messages returned.
PROCESS_INBOX_ONLY = os.environ.get("PROCESS_INBOX_ONLY", "false").lower() in (
    "1",
    "true",
    "yes",
    "on",
)

# If true, only process UNREAD messages in /run-labeler
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
    """
    in_inbox = "INBOX" in label_ids

    category_map = {
        "CATEGORY_PERSONAL": "Primary",
        "CATEGORY_PROMOTIONS": "Promotions",
        "CATEGORY_SOCIAL": "Social",
        "CATEGORY_UPDATES": "Updates",
        "CATEGORY_FORUMS": "Forums",
    }
    category = None
    for k, v in category_map.items():
        if k in label_ids:
            category = v
            break

    return {"in_inbox": in_inbox, "category": category}


def _is_free_email_domain(domain: str) -> bool:
    free_domains = {
        "gmail.com",
        "googlemail.com",
        "yahoo.com",
        "outlook.com",
        "hotmail.com",
        "live.com",
        "icloud.com",
        "me.com",
        "aol.com",
        "protonmail.com",
        "pm.me",
        "mail.com",
        "gmx.com",
    }
    return domain.lower().strip() in free_domains


def _normalize_sender_email(sender_email: str) -> str:
    return (sender_email or "").strip().lower()


def _sender_domain(sender_email: str) -> str:
    sender_email = _normalize_sender_email(sender_email)
    if "@" not in sender_email:
        return ""
    return sender_email.split("@", 1)[1]


def _should_skip_sender_for_learning(sender_email: str) -> bool:
    if not sender_email:
        return True
    dom = _sender_domain(sender_email)
    if not dom:
        return True
    if SENDER_RULES_SKIP_FREE_DOMAINS and _is_free_email_domain(dom):
        return True
    return False


def _gmail_query_for_run_labeler() -> str:
    """
    Build the Gmail search query for /run-labeler based on env configuration.
    Default uses CATEGORY_PERSONAL and unread only.
    """
    parts = []

    # Category
    if SOURCE_CATEGORY_LABEL:
        parts.append(f"label:{SOURCE_CATEGORY_LABEL}")

    # Only inbox?
    if PROCESS_INBOX_ONLY:
        parts.append("in:inbox")

    # Only unread?
    if PROCESS_UNREAD_ONLY:
        parts.append("is:unread")

    return " ".join(parts).strip()


def _remove_inbox_label_if_enabled(service, msg_id: str):
    if not REMOVE_FROM_INBOX_ON_LABEL:
        return
    try:
        service.users().messages().modify(
            userId="me",
            id=msg_id,
            body={"removeLabelIds": ["INBOX"]},
        ).execute()
    except Exception:
        logger.exception("Failed to remove INBOX label from message %s", msg_id)


def _archive_if_enabled(service, msg_id: str, is_ai: bool):
    """
    Archive means remove INBOX label. (Gmail doesn't have a separate archive label.)
    """
    if is_ai and not ARCHIVE_AI_LABELED:
        return
    if (not is_ai) and not ARCHIVE_RULE_LABELED:
        return
    try:
        service.users().messages().modify(
            userId="me",
            id=msg_id,
            body={"removeLabelIds": ["INBOX"]},
        ).execute()
    except Exception:
        logger.exception("Failed to archive (remove INBOX) message %s", msg_id)


def _label_message_flow(service, msg_id: str, label_name: str, is_ai: bool, from_address: str, subject: str):
    """
    Apply a label, record in DB, and do configured inbox removal/archiving.
    """
    label_id = get_or_create_gmail_label(service, label_name)
    apply_label_to_message(service, msg_id, label_id)

    # Record the labeled email in DB
    try:
        record_labeled_email(
            message_id=msg_id,
            label_applied=label_name,
            source="ai" if is_ai else "rule",
            from_address=from_address,
            subject=subject,
        )
    except Exception:
        logger.exception("Failed to record labeled email %s", msg_id)

    # Remove from inbox behavior
    _remove_inbox_label_if_enabled(service, msg_id)

    # Archive behavior (also removes from inbox)
    _archive_if_enabled(service, msg_id, is_ai=is_ai)


# -----------------------------
# Pages
# -----------------------------

@rules_bp.route("/", methods=["GET"])
def index():
    # Keep / as the app home, but send users to the dashboard page.
    return redirect(url_for("rules.dashboard_page"))


@rules_bp.route("/dashboard", methods=["GET"])
def dashboard_page():
    return render_template("dashboard.html")


@rules_bp.route("/rules", methods=["GET"])
def rules_page():
    return render_template("rules.html")


@rules_bp.route("/relabel", methods=["GET"])
def relabel_page():
    return render_template("relabel.html")


# -----------------------------
# API endpoints (these MUST match what your templates JS calls)
# -----------------------------

@rules_bp.route("/api/allowed-ai-labels", methods=["GET"])
def allowed_ai_labels():
    labels = get_allowed_ai_labels()
    return jsonify({"labels": labels})


@rules_bp.route("/api/rules", methods=["GET"])
def get_rules():
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute(
        """
        SELECT id, label_name, from_contains, subject_contains, body_contains, is_active, mark_read
        FROM rules
        ORDER BY id DESC
        """
    )
    rows = cur.fetchall()
    conn.close()

    results = []
    for r in rows:
        results.append(
            {
                "id": r["id"],
                "label_name": r["label_name"],
                "from_contains": r["from_contains"],
                "subject_contains": r["subject_contains"],
                "body_contains": r["body_contains"],
                "is_active": bool(r["is_active"]),
                "mark_read": bool(r["mark_read"]),
            }
        )
    return jsonify({"rules": results})


@rules_bp.route("/api/rules", methods=["POST"])
def create_rule():
    data = request.get_json(force=True, silent=True) or {}
    label_name = (data.get("label_name") or "").strip()
    from_contains = (data.get("from_contains") or "").strip()
    subject_contains = (data.get("subject_contains") or "").strip()
    body_contains = (data.get("body_contains") or "").strip()
    is_active = 1 if bool(data.get("is_active", True)) else 0
    mark_read = 1 if bool(data.get("mark_read", False)) else 0

    if not label_name:
        return jsonify({"error": "label_name is required"}), 400

    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute(
        """
        INSERT INTO rules (label_name, from_contains, subject_contains, body_contains, is_active, mark_read)
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (label_name, from_contains, subject_contains, body_contains, is_active, mark_read),
    )
    conn.commit()
    new_id = cur.lastrowid
    conn.close()

    return jsonify({"status": "ok", "id": new_id})


@rules_bp.route("/api/rules/<int:rule_id>", methods=["PUT"])
def update_rule(rule_id: int):
    data = request.get_json(force=True, silent=True) or {}
    label_name = (data.get("label_name") or "").strip()
    from_contains = (data.get("from_contains") or "").strip()
    subject_contains = (data.get("subject_contains") or "").strip()
    body_contains = (data.get("body_contains") or "").strip()
    is_active = 1 if bool(data.get("is_active", True)) else 0
    mark_read = 1 if bool(data.get("mark_read", False)) else 0

    if not label_name:
        return jsonify({"error": "label_name is required"}), 400

    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute(
        """
        UPDATE rules
        SET label_name = ?, from_contains = ?, subject_contains = ?, body_contains = ?, is_active = ?, mark_read = ?
        WHERE id = ?
        """,
        (label_name, from_contains, subject_contains, body_contains, is_active, mark_read, rule_id),
    )
    conn.commit()
    conn.close()

    return jsonify({"status": "ok"})


@rules_bp.route("/api/rules/<int:rule_id>", methods=["DELETE"])
def delete_rule(rule_id: int):
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("DELETE FROM rules WHERE id = ?", (rule_id,))
    conn.commit()
    conn.close()
    return jsonify({"status": "ok"})


@rules_bp.route("/api/gmail-labels", methods=["GET"])
def get_gmail_labels():
    try:
        service = get_gmail_service_for_current_user()
    except RuntimeError as e:
        return jsonify({"error": str(e)}), 401
    except Exception as e:
        logger.exception("Gmail auth failed in get_gmail_labels")
        return jsonify({"error": f"Gmail auth failed: {e}"}), 500

    resp = service.users().labels().list(userId="me").execute()
    labels = resp.get("labels", [])

    # Sort by name for UI
    labels_sorted = sorted(labels, key=lambda x: (x.get("name") or "").lower())

    return jsonify({"labels": labels_sorted})


@rules_bp.route("/api/labels", methods=["GET"])
def labels_counts():
    """
    Returns label counts for UI.
    """
    try:
        service = get_gmail_service_for_current_user()
    except RuntimeError as e:
        return jsonify({"error": str(e)}), 401
    except Exception as e:
        logger.exception("Gmail auth failed in labels_counts")
        return jsonify({"error": f"Gmail auth failed: {e}"}), 500

    resp = service.users().labels().list(userId="me").execute()
    labels = resp.get("labels", [])

    results = []
    for lbl in labels:
        lid = lbl.get("id")
        name = lbl.get("name")
        try:
            detail = service.users().labels().get(userId="me", id=lid).execute()
            unread = detail.get("messagesUnread", 0)
            total = detail.get("messagesTotal", 0)
        except Exception:
            unread = 0
            total = 0

        results.append({"id": lid, "name": name, "unread": unread, "total": total})

    # Sort
    results.sort(key=lambda x: (x["name"] or "").lower())
    return jsonify({"labels": results})


@rules_bp.route("/api/labels/<label_id>/mark-read", methods=["POST"])
def mark_label_read(label_id):
    """
    Marks ALL messages in a label as read (removes UNREAD label from those messages).
    """
    try:
        service = get_gmail_service_for_current_user()
    except RuntimeError as e:
        return jsonify({"error": str(e)}), 401
    except Exception as e:
        logger.exception("Gmail auth failed in mark_label_read")
        return jsonify({"error": f"Gmail auth failed: {e}"}), 500

    processed = 0
    page_token = None
    while True:
        resp = service.users().messages().list(
            userId="me",
            labelIds=[label_id],
            maxResults=500,
            pageToken=page_token,
        ).execute()

        messages = resp.get("messages", [])
        if not messages:
            break

        for m in messages:
            mid = m.get("id")
            if not mid:
                continue
            try:
                service.users().messages().modify(
                    userId="me",
                    id=mid,
                    body={"removeLabelIds": ["UNREAD"]},
                ).execute()
                processed += 1
            except Exception:
                logger.exception("Failed to mark read %s", mid)

        page_token = resp.get("nextPageToken")
        if not page_token:
            break

    return jsonify({"status": "ok", "processed": processed})


@rules_bp.route("/download-run-log", methods=["GET"])
def download_run_log():
    """
    Download the last run log file (JSONL).
    """
    path = _run_log_path()
    if not os.path.exists(path):
        return "No run log found", 404

    return send_file(path, as_attachment=True, download_name=RUN_LOG_FILENAME)


@rules_bp.route("/run-labeler", methods=["POST"])
def run_labeler():
    """
    Main labeler endpoint (original path expected by UI):
    - Fetch messages from configured source (category/inbox/unread)
    - Apply DB rules first
    - Otherwise AI suggest label
    - Apply and record
    """
    try:
        service = get_gmail_service_for_current_user()
    except RuntimeError as e:
        return jsonify({"error": str(e)}), 401
    except Exception as e:
        logger.exception("Gmail auth failed in run_labeler")
        return jsonify({"error": f"Gmail auth failed: {e}"}), 500

    query = _gmail_query_for_run_labeler()

    # Prepare run log (overwrite each run)
    log_path = _run_log_path()
    try:
        with open(log_path, "w", encoding="utf-8") as fp:
            _log_line(
                fp,
                {
                    "ts": _utc_ts(),
                    "event": "run_start",
                    "query": query,
                    "max_emails": MAX_EMAILS_PER_RUN,
                    "source_category_label": SOURCE_CATEGORY_LABEL,
                    "process_inbox_only": PROCESS_INBOX_ONLY,
                    "process_unread_only": PROCESS_UNREAD_ONLY,
                },
            )
    except Exception:
        logger.exception("Failed to open run log file %s", log_path)

    # Load rules
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute(
        """
        SELECT id, label_name, from_contains, subject_contains, body_contains, is_active, mark_read
        FROM rules
        WHERE is_active = 1
        ORDER BY id DESC
        """
    )
    rules = cur.fetchall()
    conn.close()

    # Gmail fetch messages
    total = 0
    rule_count = 0
    ai_count = 0

    try:
        resp = service.users().messages().list(userId="me", q=query, maxResults=MAX_EMAILS_PER_RUN).execute()
        messages = resp.get("messages", []) or []
    except HttpError:
        logger.exception("Gmail list failed")
        return jsonify({"error": "Gmail list failed"}), 500

    # We'll sync sender rules after run (existing behavior)
    sender_sync_summary = None

    for m in messages:
        msg_id = m.get("id")
        if not msg_id:
            continue

        total += 1

        try:
            msg = service.users().messages().get(userId="me", id=msg_id, format="full").execute()
        except HttpError:
            logger.exception("Failed to get message %s", msg_id)
            continue

        fields = extract_email_fields(msg)
        from_address = fields.get("from_address", "")
        subject = fields.get("subject", "")
        snippet = fields.get("snippet", "")
        body_text = fields.get("body_text", "")
        label_ids = fields.get("label_ids", []) or []

        mailbox = _derive_mailbox_and_category(label_ids)

        applied_label_name = None
        applied_via = None
        mark_read = False

        # 1) Try DB rules first
        for r in rules:
            r_from = (r["from_contains"] or "").strip().lower()
            r_subj = (r["subject_contains"] or "").strip().lower()
            r_body = (r["body_contains"] or "").strip().lower()

            hay_from = (from_address or "").lower()
            hay_subj = (subject or "").lower()
            hay_body = (body_text or "").lower()

            if r_from and r_from not in hay_from:
                continue
            if r_subj and r_subj not in hay_subj:
                continue
            if r_body and r_body not in hay_body:
                continue

            applied_label_name = r["label_name"]
            applied_via = "rule"
            mark_read = bool(r["mark_read"])
            break

        # 2) AI label suggestion if no rule match
        if not applied_label_name:
            allowed = get_allowed_ai_labels()
            try:
                suggested = ai_suggest_label(
                    from_address=from_address,
                    subject=subject,
                    snippet=snippet,
                    body_text=body_text,
                    allowed_labels=allowed,
                )
            except Exception:
                logger.exception("AI label suggestion failed")
                suggested = None

            if suggested and suggested in allowed:
                applied_label_name = suggested
                applied_via = "ai"
                record_ai_suggestion(msg_id, from_address, subject, suggested)

        if not applied_label_name:
            # Log no_label
            try:
                with open(log_path, "a", encoding="utf-8") as fp:
                    _log_line(
                        fp,
                        {
                            "ts": _utc_ts(),
                            "event": "no_label",
                            "message_id": msg_id,
                            "from_address": from_address,
                            "subject": subject,
                            "mailbox": mailbox,
                            "internal_date": _ms_epoch_to_iso(msg.get("internalDate")),
                        },
                    )
            except Exception:
                logger.exception("Failed to append to run log")
            continue

        # Ensure label exists and apply
        try:
            label_id = get_or_create_gmail_label(service, applied_label_name)
            apply_label_to_message(service, msg_id, label_id)

            # Mark read if requested
            if mark_read:
                try:
                    service.users().messages().modify(
                        userId="me",
                        id=msg_id,
                        body={"removeLabelIds": ["UNREAD"]},
                    ).execute()
                except Exception:
                    logger.exception("Failed to mark read %s", msg_id)

            # Record
            record_labeled_email(
                message_id=msg_id,
                label_applied=applied_label_name,
                source=applied_via,
                from_address=from_address,
                subject=subject,
            )

            # remove inbox if configured
            if REMOVE_FROM_INBOX_ON_LABEL:
                _remove_inbox_label_if_enabled(service, msg_id)

            # archive behavior
            _archive_if_enabled(service, msg_id, is_ai=(applied_via == "ai"))

            if applied_via == "rule":
                rule_count += 1
            else:
                ai_count += 1

            try:
                with open(log_path, "a", encoding="utf-8") as fp:
                    _log_line(
                        fp,
                        {
                            "ts": _utc_ts(),
                            "event": "labeled_" + applied_via,
                            "message_id": msg_id,
                            "from_address": from_address,
                            "subject": subject,
                            "label": applied_label_name,
                            "mailbox": mailbox,
                            "internal_date": _ms_epoch_to_iso(msg.get("internalDate")),
                        },
                    )
            except Exception:
                logger.exception("Failed to append to run log")

        except Exception:
            logger.exception("Failed to apply label to %s", msg_id)
            continue

    # Sync sender rules from existing @LL-* labels (existing behavior)
    try:
        sender_sync_summary = sync_sender_email_rules_from_ll_labels()
    except Exception:
        logger.exception("sync_sender_email_rules_from_ll_labels failed")
        sender_sync_summary = {"error": "sync failed"}

    # finalize run log
    try:
        with open(log_path, "a", encoding="utf-8") as fp:
            _log_line(
                fp,
                {
                    "ts": _utc_ts(),
                    "event": "run_end",
                    "processed": total,
                    "rule_labeled": rule_count,
                    "ai_labeled": ai_count,
                    "sender_rule_sync": sender_sync_summary,
                },
            )
    except Exception:
        logger.exception("Failed to append run_end to run log")

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
