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
    get_message_headers_and_snippet,
    get_message_plain_text,
)
from ll_rules import (
    load_active_rules,
    evaluate_rules_for_email,
    label_from_rule_result,
)
from ai_labeler import suggest_labels_for_email

logger = logging.getLogger(__name__)

rules_bp = Blueprint("rules", __name__, template_folder="templates")

# ----------------------------
# Env-based behavior
# ----------------------------

# When True, remove INBOX label after applying @LL-* label (it leaves Inbox, unread count drops).
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

# If true, only process unread Inbox messages in /run-labeler.
PROCESS_UNREAD_ONLY = os.environ.get("PROCESS_UNREAD_ONLY", "true").lower() in (
    "1",
    "true",
    "yes",
    "on",
)

ARCHIVE_RULE_LABELED = os.environ.get("ARCHIVE_RULE_LABELED", "false").lower() in (
    "1",
    "true",
    "yes",
    "on",
)

ARCHIVE_AI_LABELED = os.environ.get("ARCHIVE_AI_LABELED", "false").lower() in (
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
    return datetime.utcnow().isoformat() + "Z"


# NEW: sender-email learning config
LL_LABEL_PREFIX = os.environ.get("LL_LABEL_PREFIX", "@LL-")
try:
    SENDER_RULES_MAX_PER_LABEL = int(os.environ.get("SENDER_RULES_MAX_PER_LABEL", "25"))
    if SENDER_RULES_MAX_PER_LABEL <= 0:
        SENDER_RULES_MAX_PER_LABEL = 25
except ValueError:
    SENDER_RULES_MAX_PER_LABEL = 25

SENDER_RULES_SKIP_FREE_DOMAINS = os.environ.get("SENDER_RULES_SKIP_FREE_DOMAINS", "false").lower() in (
    "1",
    "true",
    "yes",
    "on",
)


def _extract_sender_email(headers: dict) -> str:
    """
    Extract email address from From header.
    headers: dict from get_message_headers_and_snippet
    """
    from_header = (headers or {}).get("From", "") or ""
    from_header = from_header.strip()
    if "<" in from_header and ">" in from_header:
        # Name <email@domain.com>
        try:
            return from_header.split("<", 1)[1].split(">", 1)[0].strip().lower()
        except Exception:
            return from_header.lower()
    return from_header.lower()


def _domain_of(email: str) -> str:
    if "@" in (email or ""):
        return email.split("@", 1)[1].lower().strip()
    return ""


FREE_EMAIL_DOMAINS = {
    "gmail.com",
    "yahoo.com",
    "outlook.com",
    "hotmail.com",
    "aol.com",
    "icloud.com",
    "me.com",
    "live.com",
    "msn.com",
    "proton.me",
    "protonmail.com",
    "gmx.com",
}


def sync_sender_email_rules_from_ll_labels(
    service,
    label_prefix: str = "@LL-",
    max_per_label: int = 25,
    skip_free_email_domains: bool = False,
):
    """
    Learn/overwrite sender-email rules by scanning messages inside ANY @LL-* label.
    Strategy:
      - For each label starting with label_prefix, grab up to max_per_label recent *UNREAD* messages,
        extract sender email, and upsert sender rule mapping sender_email -> that label.
      - Latest wins if sender appears under multiple labels (within the scan order).
    """
    summary = {
        "status": "ok",
        "labels_scanned": 0,
        "messages_scanned": 0,
        "created_or_updated": 0,
        "skipped_free_domain": 0,
        "errors": 0,
    }

    try:
        # list all labels
        lbl_resp = service.users().labels().list(userId="me").execute()
        labels = lbl_resp.get("labels", [])
    except Exception as e:
        summary["status"] = "error"
        summary["errors"] += 1
        summary["error"] = str(e)
        return summary

    ll_labels = [l for l in labels if (l.get("name") or "").startswith(label_prefix)]
    summary["labels_scanned"] = len(ll_labels)

    conn = get_db_connection()
    try:
        for l in ll_labels:
            label_id = l.get("id")
            label_name = l.get("name")

            page_token = None
            pulled = 0

            while True:
                resp = (
                    service.users()
                    .messages()
                    .list(
                        userId="me",
                        labelIds=[label_id, "UNREAD"],
                        pageToken=page_token,
                        maxResults=min(100, max_per_label - pulled),
                    )
                    .execute()
                )

                msgs = resp.get("messages", [])
                if not msgs:
                    break

                for m in msgs:
                    if pulled >= max_per_label:
                        break

                    msg_id = m.get("id")
                    try:
                        headers, _snippet = get_message_headers_and_snippet(service, msg_id)
                        sender = _extract_sender_email(headers)
                        if not sender:
                            continue

                        if skip_free_email_domains:
                            dom = _domain_of(sender)
                            if dom in FREE_EMAIL_DOMAINS:
                                summary["skipped_free_domain"] += 1
                                continue

                        # Upsert sender rule
                        cur = conn.cursor()
                        cur.execute(
                            """
                            INSERT INTO sender_email_rules (sender_email, target_label)
                            VALUES (?, ?)
                            ON CONFLICT(sender_email) DO UPDATE SET
                                target_label=excluded.target_label,
                                updated_at=CURRENT_TIMESTAMP
                            """,
                            (sender, label_name),
                        )
                        conn.commit()

                        summary["created_or_updated"] += 1
                        summary["messages_scanned"] += 1
                        pulled += 1
                    except Exception:
                        summary["errors"] += 1
                        logger.exception("Error scanning message for sender rule: label=%s msg=%s", label_name, msg_id)

                page_token = resp.get("nextPageToken")
                if not page_token:
                    break
                if pulled >= max_per_label:
                    break

    finally:
        try:
            conn.close()
        except Exception:
            pass

    return summary


@rules_bp.route("/rules")
def rules_page():
    rules = load_active_rules()
    return render_template("rules.html", rules=rules)


@rules_bp.route("/api/rules")
def api_rules():
    rules = load_active_rules()
    return jsonify({"rules": rules})


@rules_bp.route("/download-run-log", methods=["GET"])
def download_run_log():
    path = _run_log_path()
    if not os.path.exists(path):
        return jsonify({"error": "No run log found yet."}), 404
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

    # Create/overwrite run log
    fp = None
    log_path = _run_log_path()
    try:
        fp = open(log_path, "w", encoding="utf-8")
        logger.info("Writing run log at %s", log_path)
    except Exception:
        fp = None
        logger.exception("Failed to open run log path: %s", log_path)

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

    try:
        # IMPORTANT: Only process unread inbox if PROCESS_UNREAD_ONLY=true
        msg_list = (
            service.users()
            .messages()
            .list(
                userId="me",
                labelIds=(["INBOX", "UNREAD"] if PROCESS_UNREAD_ONLY else ["INBOX"]),
                maxResults=MAX_EMAILS_PER_RUN,
            )
            .execute()
        )

        messages = msg_list.get("messages", [])

        if fp:
            _log_line(
                fp,
                {
                    "ts": _utc_ts(),
                    "event": "fetched_messages",
                    "count": len(messages),
                    "label_filter": (["INBOX", "UNREAD"] if PROCESS_UNREAD_ONLY else ["INBOX"]),
                },
            )

        for msg in messages:
            msg_id = msg["id"]
            total += 1

            try:
                headers, snippet = get_message_headers_and_snippet(service, msg_id)
                subject = headers.get("Subject", "")
                from_ = headers.get("From", "")

                plain_text = get_message_plain_text(service, msg_id)

                if fp:
                    _log_line(
                        fp,
                        {
                            "ts": _utc_ts(),
                            "event": "email_loaded",
                            "message_id": msg_id,
                            "subject": subject,
                            "from": from_,
                        },
                    )

                # 1) Evaluate rules
                rule_result = evaluate_rules_for_email(rules, headers, snippet, plain_text)

                if rule_result:
                    label_name = label_from_rule_result(rule_result)
                    if label_name:
                        label_id = get_or_create_gmail_label(service, label_name)

                        apply_label_to_message(
                            service,
                            msg_id,
                            add_label_ids=[label_id],
                            remove_from_inbox=REMOVE_FROM_INBOX_ON_LABEL,
                            archive=ARCHIVE_RULE_LABELED,
                        )

                        record_labeled_email(
                            message_id=msg_id,
                            label_applied=label_name,
                            source="rule",
                            subject=subject,
                            sender=from_,
                        )
                        rule_count += 1

                        if fp:
                            _log_line(
                                fp,
                                {
                                    "ts": _utc_ts(),
                                    "event": "labeled_by_rule",
                                    "message_id": msg_id,
                                    "label": label_name,
                                    "rule_id": rule_result.get("rule_id"),
                                },
                            )

                        continue  # do not AI-label if rule matched

                # 2) AI suggestion if no rule match
                ai_suggestion = suggest_labels_for_email(headers, snippet, plain_text)

                if ai_suggestion and ai_suggestion.get("label"):
                    label_name = ai_suggestion["label"]
                    label_id = get_or_create_gmail_label(service, label_name)

                    apply_label_to_message(
                        service,
                        msg_id,
                        add_label_ids=[label_id],
                        remove_from_inbox=REMOVE_FROM_INBOX_ON_LABEL,
                        archive=ARCHIVE_AI_LABELED,
                    )

                    record_ai_suggestion(
                        message_id=msg_id,
                        suggested_label=label_name,
                        confidence=ai_suggestion.get("confidence"),
                        reasoning=ai_suggestion.get("reasoning"),
                        subject=subject,
                        sender=from_,
                    )

                    ai_count += 1

                    if fp:
                        _log_line(
                            fp,
                            {
                                "ts": _utc_ts(),
                                "event": "labeled_by_ai",
                                "message_id": msg_id,
                                "label": label_name,
                                "confidence": ai_suggestion.get("confidence"),
                            },
                        )

            except HttpError as e:
                logger.exception("Gmail API error processing message_id=%s", msg_id)
                if fp:
                    _log_line(
                        fp,
                        {
                            "ts": _utc_ts(),
                            "event": "error",
                            "message_id": msg_id,
                            "error": str(e),
                        },
                    )
            except Exception as e:
                logger.exception("Unexpected error processing message_id=%s", msg_id)
                if fp:
                    _log_line(
                        fp,
                        {
                            "ts": _utc_ts(),
                            "event": "error",
                            "message_id": msg_id,
                            "error": str(e),
                        },
                    )

    finally:
        if fp:
            _log_line(
                fp,
                {
                    "ts": _utc_ts(),
                    "event": "run_end",
                    "total_processed": total,
                    "rule_labeled": rule_count,
                    "ai_labeled": ai_count,
                    "sender_rule_sync": sender_sync_summary,
                },
            )
            try:
                fp.close()
            except Exception:
                pass

    return jsonify(
        {
            "status": "ok",
            "processed": total,
            "rule_labeled": rule_count,
            "ai_labeled": ai_count,
            "sender_rule_sync": sender_sync_summary,
            "process_unread_only": PROCESS_UNREAD_ONLY,
        }
    )
