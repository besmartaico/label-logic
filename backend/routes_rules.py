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


def _safe_str(x):
    if x is None:
        return ""
    return str(x)


def _bool_param(name: str, default: bool = False) -> bool:
    raw = request.args.get(name)
    if raw is None:
        return default
    return raw.strip().lower() in ("1", "true", "yes", "on", "y")


def _int_param(name: str, default: int) -> int:
    raw = request.args.get(name)
    if raw is None:
        return default
    try:
        return int(raw)
    except Exception:
        return default


def _json_body():
    try:
        return request.get_json(force=True, silent=True) or {}
    except Exception:
        return {}


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


def _get_messages(service, query: str, max_results: int):
    """
    Return list of message stubs with id/threadId.
    """
    resp = service.users().messages().list(userId="me", q=query, maxResults=max_results).execute()
    return resp.get("messages", []) or []


def _get_message_full(service, msg_id: str):
    """
    Fetch full message.
    """
    return service.users().messages().get(userId="me", id=msg_id, format="full").execute()


def _extract_fields(msg):
    """
    Extract common fields from a Gmail message using helper.
    """
    try:
        return extract_email_fields(msg)
    except Exception:
        logger.exception("Failed to extract email fields")
        return {
            "from_address": "",
            "to_address": "",
            "subject": "",
            "snippet": "",
            "date": "",
            "body_text": "",
            "label_ids": msg.get("labelIds", []) if isinstance(msg, dict) else [],
        }


def _apply_sender_rule_if_any(service, msg_id: str, from_address: str, subject: str):
    """
    Apply a learned sender-email rule if present (stored in DB).
    """
    sender = _normalize_sender_email(from_address)
    if not sender:
        return None

    try:
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute(
            """
            SELECT label_name
            FROM sender_email_rules
            WHERE sender_email = ?
            ORDER BY updated_at DESC
            LIMIT 1
            """,
            (sender,),
        )
        row = cur.fetchone()
        conn.close()
    except Exception:
        logger.exception("Failed to query sender_email_rules")
        return None

    if not row:
        return None

    label_name = row["label_name"] if isinstance(row, dict) or hasattr(row, "__getitem__") else row[0]
    if not label_name:
        return None

    try:
        _label_message_flow(
            service=service,
            msg_id=msg_id,
            label_name=label_name,
            is_ai=False,
            from_address=from_address,
            subject=subject,
        )
        return label_name
    except Exception:
        logger.exception("Failed to apply sender rule label to message %s", msg_id)
        return None


def _is_valid_email_label(label_name: str) -> bool:
    """
    Only allow labels that are in the allowed LL label set (or default list).
    """
    allowed = get_allowed_ai_labels()
    return label_name in allowed


def _maybe_ai_suggest_label(from_address: str, subject: str, snippet: str, body_text: str):
    """
    Ask the AI to suggest a label. Returns label name or None.
    """
    try:
        allowed = get_allowed_ai_labels()
        suggestion = ai_suggest_label(
            from_address=from_address,
            subject=subject,
            snippet=snippet,
            body_text=body_text,
            allowed_labels=allowed,
        )
        if not suggestion:
            return None
        suggestion = suggestion.strip()
        if suggestion not in allowed:
            return None
        return suggestion
    except Exception:
        logger.exception("AI label suggestion failed")
        return None


def _record_ai_suggestion(msg_id: str, from_address: str, subject: str, suggested_label: str):
    try:
        record_ai_suggestion(
            message_id=msg_id,
            from_address=from_address,
            subject=subject,
            suggested_label=suggested_label,
        )
    except Exception:
        logger.exception("Failed to record AI suggestion for message %s", msg_id)


def _is_gmail_http_error(e: Exception) -> bool:
    return isinstance(e, HttpError)


def _http_error_status(e: HttpError) -> int | None:
    try:
        return int(getattr(e.resp, "status", None))
    except Exception:
        return None


def _json_error(msg: str, status: int = 400, extra: dict | None = None):
    data = {"error": msg}
    if extra:
        data.update(extra)
    return jsonify(data), status


# -----------------------------
# Pages
# -----------------------------

@rules_bp.route("/", methods=["GET"])
def index():
    # App home
    return redirect(url_for("rules.dashboard_page"))


@rules_bp.route("/dashboard", methods=["GET"])
def dashboard_page():
    return render_template("dashboard.html")


@rules_bp.route("/rules", methods=["GET"])
def rules_page():
    return render_template("rules.html")


@rules_bp.route("/ai-labels", methods=["GET"])
def ai_labels_page():
    return render_template("ai_labels.html")


@rules_bp.route("/relabel", methods=["GET"])
def relabel_page():
    return render_template("relabel.html")


# -----------------------------
# API: labels and rules
# -----------------------------

@rules_bp.route("/api/ll-labels", methods=["GET"])
def api_ll_labels():
    labels = get_allowed_ai_labels()
    return jsonify({"labels": labels})


@rules_bp.route("/api/default-ll-labels", methods=["GET"])
def api_default_ll_labels():
    return jsonify({"labels": DEFAULT_LL_LABELS})


@rules_bp.route("/api/sync-sender-rules", methods=["POST"])
def api_sync_sender_rules():
    """
    Sync sender_email_rules based on existing labeled emails in DB.
    (Keeps sender rules aligned with @LL labels in the mailbox.)
    """
    try:
        result = sync_sender_email_rules_from_ll_labels(
            label_prefix=LL_LABEL_PREFIX,
            max_per_label=SENDER_RULES_MAX_PER_LABEL,
            skip_free_domains=SENDER_RULES_SKIP_FREE_DOMAINS,
        )
        return jsonify({"ok": True, "result": result})
    except Exception as e:
        logger.exception("sync_sender_email_rules failed")
        return _json_error("Failed to sync sender rules", 500, {"message": str(e)})


@rules_bp.route("/api/learn-rules", methods=["POST"])
def api_learn_rules():
    """
    Learn sender-email rules from the labeled emails log.
    """
    try:
        result = learn_rules_from_labeled_emails(
            label_prefix=LL_LABEL_PREFIX,
            max_per_label=SENDER_RULES_MAX_PER_LABEL,
            skip_free_domains=SENDER_RULES_SKIP_FREE_DOMAINS,
        )
        return jsonify({"ok": True, "result": result})
    except Exception as e:
        logger.exception("learn_rules_from_labeled_emails failed")
        return _json_error("Failed to learn rules", 500, {"message": str(e)})


@rules_bp.route("/api/run-labeler", methods=["POST"])
def run_labeler():
    """
    Main labeler endpoint:
    - Fetch messages from configured source (category/inbox/unread)
    - Apply sender rules if available
    - Otherwise ask AI for a suggestion (optional)
    - Apply labels and record logs
    """
    body = _json_body()
    max_emails = int(body.get("max_emails") or MAX_EMAILS_PER_RUN)

    query_override = body.get("query")
    query = (query_override or _gmail_query_for_run_labeler()).strip()

    # Allow caller to override unread-only/inbox-only behavior by passing a query
    if not query:
        query = _gmail_query_for_run_labeler()

    try:
        service = get_gmail_service_for_current_user()
    except Exception as e:
        logger.exception("Failed to get Gmail service")
        return _json_error("Not authenticated with Gmail", 401, {"message": str(e)})

    # Prepare run log
    log_path = _run_log_path()
    run_meta = {
        "ts": _utc_ts(),
        "event": "run_start",
        "query": query,
        "max_emails": max_emails,
        "source_category_label": SOURCE_CATEGORY_LABEL,
        "process_inbox_only": PROCESS_INBOX_ONLY,
        "process_unread_only": PROCESS_UNREAD_ONLY,
    }
    try:
        with open(log_path, "w", encoding="utf-8") as fp:
            _log_line(fp, run_meta)
    except Exception:
        logger.exception("Failed to open run log file %s", log_path)

    processed = 0
    labeled = 0
    ai_suggested = 0
    errors = 0

    try:
        msgs = _get_messages(service, query=query, max_results=max_emails)
    except HttpError as e:
        logger.exception("Gmail list failed")
        status = _http_error_status(e) or 500
        return _json_error("Gmail API error listing messages", status, {"message": str(e)})

    for m in msgs:
        msg_id = m.get("id")
        if not msg_id:
            continue

        processed += 1

        try:
            msg = _get_message_full(service, msg_id)
            fields = _extract_fields(msg)

            from_address = fields.get("from_address", "")
            subject = fields.get("subject", "")
            snippet = fields.get("snippet", "")
            body_text = fields.get("body_text", "")
            label_ids = fields.get("label_ids", []) or []

            mailbox = _derive_mailbox_and_category(label_ids)

            # 1) Try sender rule
            applied_rule_label = _apply_sender_rule_if_any(service, msg_id, from_address, subject)
            if applied_rule_label:
                labeled += 1
                try:
                    with open(log_path, "a", encoding="utf-8") as fp:
                        _log_line(
                            fp,
                            {
                                "ts": _utc_ts(),
                                "event": "labeled_rule",
                                "message_id": msg_id,
                                "from_address": from_address,
                                "subject": subject,
                                "label": applied_rule_label,
                                "mailbox": mailbox,
                                "internal_date": _ms_epoch_to_iso(msg.get("internalDate")),
                            },
                        )
                except Exception:
                    logger.exception("Failed to append to run log")
                continue

            # 2) AI suggestion
            suggested = _maybe_ai_suggest_label(from_address, subject, snippet, body_text)
            if suggested:
                ai_suggested += 1
                _record_ai_suggestion(msg_id, from_address, subject, suggested)

                # Apply AI label immediately (current behavior)
                _label_message_flow(
                    service=service,
                    msg_id=msg_id,
                    label_name=suggested,
                    is_ai=True,
                    from_address=from_address,
                    subject=subject,
                )
                labeled += 1

                try:
                    with open(log_path, "a", encoding="utf-8") as fp:
                        _log_line(
                            fp,
                            {
                                "ts": _utc_ts(),
                                "event": "labeled_ai",
                                "message_id": msg_id,
                                "from_address": from_address,
                                "subject": subject,
                                "label": suggested,
                                "mailbox": mailbox,
                                "internal_date": _ms_epoch_to_iso(msg.get("internalDate")),
                            },
                        )
                except Exception:
                    logger.exception("Failed to append to run log")

            else:
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

        except HttpError as e:
            errors += 1
            logger.exception("Gmail API error processing message %s", msg_id)
            status = _http_error_status(e) or 500
            try:
                with open(log_path, "a", encoding="utf-8") as fp:
                    _log_line(
                        fp,
                        {
                            "ts": _utc_ts(),
                            "event": "error",
                            "message_id": msg_id,
                            "error_type": "HttpError",
                            "status": status,
                            "message": str(e),
                        },
                    )
            except Exception:
                logger.exception("Failed to append error to run log")
        except Exception as e:
            errors += 1
            logger.exception("Unexpected error processing message %s", msg_id)
            try:
                with open(log_path, "a", encoding="utf-8") as fp:
                    _log_line(
                        fp,
                        {
                            "ts": _utc_ts(),
                            "event": "error",
                            "message_id": msg_id,
                            "error_type": type(e).__name__,
                            "message": str(e),
                        },
                    )
            except Exception:
                logger.exception("Failed to append error to run log")

    # finalize run log
    try:
        with open(log_path, "a", encoding="utf-8") as fp:
            _log_line(
                fp,
                {
                    "ts": _utc_ts(),
                    "event": "run_end",
                    "processed": processed,
                    "labeled": labeled,
                    "ai_suggested": ai_suggested,
                    "errors": errors,
                },
            )
    except Exception:
        logger.exception("Failed to append run_end to run log")

    return jsonify(
        {
            "ok": True,
            "query": query,
            "processed": processed,
            "labeled": labeled,
            "ai_suggested": ai_suggested,
            "errors": errors,
        }
    )


@rules_bp.route("/api/download-last-run", methods=["GET"])
def download_last_run():
    """
    Download the last run log file (JSONL).
    """
    path = _run_log_path()
    if not os.path.exists(path):
        return _json_error("No run log found", 404)

    return send_file(path, as_attachment=True, download_name=RUN_LOG_FILENAME)


@rules_bp.route("/api/apply-label", methods=["POST"])
def api_apply_label():
    """
    Apply a label to a Gmail message. Used by UI when user confirms/overrides suggestions.
    Expects JSON:
      { "message_id": "...", "label": "..." , "source": "manual"|"ai"|"rule" }
    """
    body = _json_body()
    msg_id = (body.get("message_id") or "").strip()
    label_name = (body.get("label") or "").strip()
    source = (body.get("source") or "manual").strip().lower()

    if not msg_id:
        return _json_error("message_id required", 400)
    if not label_name:
        return _json_error("label required", 400)
    if not _is_valid_email_label(label_name):
        return _json_error("Invalid label", 400, {"label": label_name})

    try:
        service = get_gmail_service_for_current_user()
    except Exception as e:
        logger.exception("Failed to get Gmail service")
        return _json_error("Not authenticated with Gmail", 401, {"message": str(e)})

    try:
        msg = _get_message_full(service, msg_id)
        fields = _extract_fields(msg)
        from_address = fields.get("from_address", "")
        subject = fields.get("subject", "")

        _label_message_flow(
            service=service,
            msg_id=msg_id,
            label_name=label_name,
            is_ai=(source == "ai"),
            from_address=from_address,
            subject=subject,
        )

        return jsonify({"ok": True, "message_id": msg_id, "label": label_name})

    except HttpError as e:
        logger.exception("Gmail API error applying label")
        status = _http_error_status(e) or 500
        return _json_error("Gmail API error applying label", status, {"message": str(e)})
    except Exception as e:
        logger.exception("Unexpected error applying label")
        return _json_error("Unexpected error applying label", 500, {"message": str(e)})
