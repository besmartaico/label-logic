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
SOURCE_CATEGORY_LABEL = (
    os.environ.get("SOURCE_CATEGORY_LABEL", "CATEGORY_PERSONAL").strip() or "CATEGORY_PERSONAL"
)

PROCESS_INBOX_ONLY = os.environ.get("PROCESS_INBOX_ONLY", "false").lower() in (
    "1",
    "true",
    "yes",
    "on",
)

PROCESS_UNREAD_ONLY = os.environ.get("PROCESS_UNREAD_ONLY", "true").lower() in (
    "1",
    "true",
    "yes",
    "on",
)

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
    if ms is None:
        return None
    try:
        ms_int = int(ms)
        dt = datetime.fromtimestamp(ms_int / 1000, tz=timezone.utc)
        return dt.isoformat().replace("+00:00", "Z")
    except Exception:
        return None


def load_all_rules():
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute(
        """
        SELECT id, label_name, from_contains, subject_contains, body_contains, is_active, mark_as_read
        FROM rules
        ORDER BY id DESC;
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
                "from_contains": r["from_contains"] or "",
                "subject_contains": r["subject_contains"] or "",
                "body_contains": r["body_contains"] or "",
                "is_active": bool(r["is_active"]),
                "mark_as_read": bool(r["mark_as_read"]),
            }
        )
    return results


def email_matches_rule(sender, subject, body, rule):
    sender = (sender or "").lower()
    subject = (subject or "").lower()
    body = (body or "").lower()

    from_contains = (rule.get("from_contains") or "").strip().lower()
    subject_contains = (rule.get("subject_contains") or "").strip().lower()
    body_contains = (rule.get("body_contains") or "").strip().lower()

    if from_contains and from_contains not in sender:
        return False
    if subject_contains and subject_contains not in subject:
        return False
    if body_contains and body_contains not in body:
        return False

    return True


def _gmail_query_for_run_labeler() -> str:
    parts = []

    if SOURCE_CATEGORY_LABEL:
        parts.append(f"label:{SOURCE_CATEGORY_LABEL}")

    if PROCESS_INBOX_ONLY:
        parts.append("in:inbox")

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


# -----------------------------
# Pages
# -----------------------------

@rules_bp.route("/", methods=["GET"])
def index():
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
# API: labels/rules
# -----------------------------

@rules_bp.route("/api/allowed-ai-labels", methods=["GET"])
def api_allowed_ai_labels():
    labels = get_allowed_ai_labels()
    return jsonify({"labels": labels})


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


@rules_bp.route("/api/labels", methods=["GET"])
def api_labels_counts():
    try:
        service = get_gmail_service_for_current_user()
    except RuntimeError as e:
        return jsonify({"error": str(e)}), 401
    except Exception as e:
        logger.exception("Gmail auth failed when fetching label counts")
        return jsonify({"error": f"Gmail auth failed: {e}"}), 500

    try:
        resp = service.users().labels().list(userId="me").execute()
        labels = resp.get("labels", [])
    except HttpError as e:
        logger.exception("Gmail labels list failed")
        return jsonify({"error": f"Gmail error: {e}"}), 500

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

    results.sort(key=lambda x: (x["name"] or "").lower())
    return jsonify({"labels": results})


@rules_bp.route("/init-default-labels", methods=["POST", "GET"])
def api_init_default_labels():
    try:
        service = get_gmail_service_for_current_user()
    except RuntimeError as e:
        return jsonify({"error": str(e)}), 401
    except Exception as e:
        logger.exception("Gmail auth failed when init default labels")
        return jsonify({"error": f"Gmail auth failed: {e}"}), 500

    ensured = []
    for name in DEFAULT_LL_LABELS:
        try:
            label_id = get_or_create_gmail_label(service, name)
            ensured.append({"name": name, "id": label_id})
        except Exception:
            logger.exception("Failed creating label %s", name)

    return jsonify({"status": "ok", "ensured": ensured})


@rules_bp.route("/download-run-log", methods=["GET"])
def download_run_log():
    path = _run_log_path()
    if not os.path.exists(path):
        return "No run log found", 404
    return send_file(path, as_attachment=True, download_name=RUN_LOG_FILENAME)


@rules_bp.route("/run-labeler", methods=["POST"])
def run_labeler():
    try:
        service = get_gmail_service_for_current_user()
    except RuntimeError as e:
        return jsonify({"error": str(e)}), 401
    except Exception as e:
        logger.exception("Gmail auth failed in run_labeler")
        return jsonify({"error": f"Gmail auth failed: {e}"}), 500

    query = _gmail_query_for_run_labeler()

    # overwrite log each run
    log_path = _run_log_path()
    try:
        with open(log_path, "w", encoding="utf-8") as fp:
            _log_line(fp, {"ts": _utc_ts(), "event": "run_start", "query": query, "max": MAX_EMAILS_PER_RUN})
    except Exception:
        logger.exception("Failed to open run log file %s", log_path)

    rules = load_all_rules()

    try:
        resp = service.users().messages().list(userId="me", q=query, maxResults=MAX_EMAILS_PER_RUN).execute()
        messages = resp.get("messages", []) or []
    except HttpError:
        logger.exception("Gmail list failed")
        return jsonify({"error": "Gmail list failed"}), 500

    total = 0
    rule_labeled = 0
    ai_labeled = 0

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
        sender = fields.get("from_address", "")
        subject = fields.get("subject", "")
        body = fields.get("body_text", "") or ""
        snippet = fields.get("snippet", "") or ""

        matched_label = None
        matched_rule_mark_read = False

        for rule in rules:
            if not rule.get("is_active", True):
                continue
            if email_matches_rule(sender, subject, body, rule):
                matched_label = rule.get("label_name")
                matched_rule_mark_read = bool(rule.get("mark_as_read", False))
                break

        applied_via = None

        if matched_label:
            applied_via = "rule"
            label_to_apply = matched_label
        else:
            allowed = get_allowed_ai_labels()
            try:
                suggested = ai_suggest_label(
                    from_address=sender,
                    subject=subject,
                    snippet=snippet,
                    body_text=body,
                    allowed_labels=allowed,
                )
            except Exception:
                logger.exception("AI label suggestion failed")
                suggested = None

            if suggested and suggested in allowed:
                applied_via = "ai"
                label_to_apply = suggested
                try:
                    record_ai_suggestion(msg_id, label_to_apply, None)
                except Exception:
                    logger.exception("record_ai_suggestion failed")
            else:
                label_to_apply = None

        if not label_to_apply:
            continue

        try:
            label_id = get_or_create_gmail_label(service, label_to_apply)
            apply_label_to_message(service, msg_id, label_id)

            if applied_via == "rule" and matched_rule_mark_read:
                try:
                    service.users().messages().modify(
                        userId="me",
                        id=msg_id,
                        body={"removeLabelIds": ["UNREAD"]},
                    ).execute()
                except Exception:
                    logger.exception("Failed to mark read %s", msg_id)

            try:
                record_labeled_email(
                    gmail_id=msg_id,
                    thread_id=msg.get("threadId"),
                    sender=sender,
                    subject=subject,
                    snippet=snippet,
                    label=label_to_apply,
                    is_ai_labeled=(applied_via == "ai"),
                    source=applied_via,
                )
            except Exception:
                logger.exception("record_labeled_email failed")

            _remove_inbox_label_if_enabled(service, msg_id)
            _archive_if_enabled(service, msg_id, is_ai=(applied_via == "ai"))

            if applied_via == "rule":
                rule_labeled += 1
            else:
                ai_labeled += 1

        except Exception:
            logger.exception("Failed to apply label %s to message %s", label_to_apply, msg_id)

    # ✅ FIX: pass the Gmail service into the sync function
    try:
        sync_sender_email_rules_from_ll_labels(service)
    except Exception:
        logger.exception("sync_sender_email_rules_from_ll_labels failed")

    return jsonify({"status": "ok", "processed": total, "rule_labeled": rule_labeled, "ai_labeled": ai_labeled})


@rules_bp.route("/learn-rules", methods=["POST"])
def learn_rules():
    try:
        created = learn_rules_from_labeled_emails()
        return jsonify({"status": "ok", "created": created})
    except Exception:
        logger.exception("learn_rules failed")
        return jsonify({"error": "learn_rules failed"}), 500
