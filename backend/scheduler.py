"""
server_scheduler.py
====================
Server-side APScheduler that runs entirely inside the Flask/Gunicorn process.
No browser needed — schedules survive server restarts (config is loaded from DB).

How it works:
1. On startup, load each user's schedule_config from user_settings.
2. For each user with run_labeler.enabled=True, add an interval job.
3. For each user with learn_rules.enabled=True, add an interval job.
4. When /api/schedule is POSTed, reschedule that user's jobs immediately.
5. Jobs run as the user by building a real Gmail service from stored credentials.
"""

import json
import logging
from datetime import datetime, timezone

from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.interval import IntervalTrigger

from db import get_db_connection, load_credentials, save_credentials
from gmail_client import GMAIL_SCOPES

logger = logging.getLogger(__name__)

_scheduler = BackgroundScheduler(timezone="UTC")
_started = False


# ─────────────────────────────────────────────
# Internal helpers
# ─────────────────────────────────────────────

def _get_gmail_service(google_user_id: str):
    """Build a Gmail service directly from stored credentials (no Flask session)."""
    from google.oauth2.credentials import Credentials
    from google.auth.transport.requests import Request as GoogleAuthRequest
    from googleapiclient.discovery import build

    creds_json = load_credentials(google_user_id)
    if not creds_json:
        raise RuntimeError(f"No credentials for user {google_user_id}")
    import json as _json
    data = _json.loads(creds_json)
    creds = Credentials.from_authorized_user_info(data, GMAIL_SCOPES)
    if not creds.valid:
        if creds.expired and creds.refresh_token:
            creds.refresh(GoogleAuthRequest())
            # Persist refreshed creds
            conn = get_db_connection()
            cur = conn.cursor()
            cur.execute("SELECT email FROM google_accounts WHERE google_user_id=%s", (google_user_id,))
            row = cur.fetchone()
            conn.close()
            email = row["email"] if row else ""
            save_credentials(google_user_id, email, creds)
        else:
            raise RuntimeError(f"Credentials invalid for user {google_user_id}")
    return build("gmail", "v1", credentials=creds)


def _save_run(google_user_id, run_type, **kwargs):
    """Persist a scheduled run result to schedule_runs table."""
    now = datetime.utcnow().isoformat(timespec="seconds")
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("""
            INSERT INTO schedule_runs
                (google_user_id, run_type, processed, rule_labeled, ai_labeled,
                 skipped, rules_created, ran_at, created_at)
            VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s)
        """, (
            google_user_id, run_type,
            kwargs.get("processed", 0),
            kwargs.get("rule_labeled", 0),
            kwargs.get("ai_labeled", 0),
            kwargs.get("skipped", 0),
            kwargs.get("rules_created", 0),
            now, now,
        ))
        conn.commit()
        conn.close()
    except Exception:
        logger.exception("Failed to save schedule run for %s", google_user_id)


# ─────────────────────────────────────────────
# Job functions
# ─────────────────────────────────────────────

def _job_run_labeler(google_user_id: str):
    """Run the labeler for one user — called by APScheduler."""
    logger.info("[scheduler] run_labeler starting for %s", google_user_id)
    try:
        from routes_rules import (
            load_active_rules, email_matches_rule,
            REMOVE_FROM_INBOX_ON_LABEL, MAX_EMAILS_PER_RUN, PROCESS_PRIMARY_ONLY,
            PROCESS_UNREAD_ONLY,
        )
        from gmail_client import apply_label_to_message, extract_email_fields
        from ai_labels import ai_suggest_label, get_allowed_ai_labels
        from db import get_db_connection, record_labeled_email, record_ai_suggestion
        import json as _json
        from datetime import datetime as _dt

        service = _get_gmail_service(google_user_id)

        # Load AI instructions for this user
        ai_instructions = ""
        try:
            conn = get_db_connection()
            cur = conn.cursor()
            cur.execute("SELECT ai_instructions FROM user_settings WHERE google_user_id=%s", (google_user_id,))
            row = cur.fetchone()
            conn.close()
            if row and row["ai_instructions"]:
                items = _json.loads(row["ai_instructions"])
                if isinstance(items, list):
                    ai_instructions = "\n".join(i["text"] for i in items if i.get("text"))
        except Exception:
            pass

        # Load this user's active rules
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("SELECT * FROM rules WHERE is_active=TRUE AND google_user_id=%s ORDER BY id", (google_user_id,))
        from routes_rules import db_row_to_rule
        rules = [db_row_to_rule(r) for r in cur.fetchall()]
        conn.close()

        label_filter = ["INBOX"]
        if PROCESS_PRIMARY_ONLY:
            label_filter.append("CATEGORY_PERSONAL")
        if PROCESS_UNREAD_ONLY:
            label_filter.append("UNREAD")

        msg_list = service.users().messages().list(
            userId="me", labelIds=label_filter, maxResults=MAX_EMAILS_PER_RUN
        ).execute()
        messages = msg_list.get("messages", [])

        total = rule_count = ai_count = 0
        for m in messages:
            total += 1
            try:
                full = service.users().messages().get(userId="me", id=m["id"], format="full").execute()
            except Exception:
                continue
            sender, subject, snippet, body = extract_email_fields(full)
            thread_id = full.get("threadId","")
            pre_label_ids = full.get("labelIds",[]) or []
            if any(lid.startswith("Label_") for lid in pre_label_ids):
                continue

            matched_label = None
            for rule in rules:
                if email_matches_rule(sender, subject, body, rule):
                    matched_label = rule["label_name"]
                    apply_label_to_message(service, m["id"], matched_label,
                                           remove_from_inbox=REMOVE_FROM_INBOX_ON_LABEL,
                                           mark_as_read=rule.get("mark_as_read", False))
                    record_labeled_email(m["id"], thread_id, sender, subject, snippet,
                                         matched_label, is_ai_labeled=False, source="rule")
                    rule_count += 1
                    break

            if not matched_label:
                label, conf = ai_suggest_label(sender, subject, body, extra_instructions=ai_instructions)
                if label:
                    apply_label_to_message(service, m["id"], label, remove_from_inbox=REMOVE_FROM_INBOX_ON_LABEL)
                    record_labeled_email(m["id"], thread_id, sender, subject, snippet,
                                         label, is_ai_labeled=True, source="ai")
                    record_ai_suggestion(m["id"], label, conf)
                    ai_count += 1
                    # Auto-create sender domain rule
                    import re as _re
                    _match = _re.search(r"@([\w.\-]+)", sender or "")
                    if _match:
                        _domain = "@" + _match.group(1).lower()
                        try:
                            conn2 = get_db_connection()
                            cur2 = conn2.cursor()
                            cur2.execute(
                                "SELECT 1 FROM rules WHERE google_user_id=%s AND label_name=%s AND from_contains=%s LIMIT 1",
                                (google_user_id, label, _domain))
                            if not cur2.fetchone():
                                _now2 = _dt.utcnow().isoformat(timespec="seconds")
                                cur2.execute("""
                                    INSERT INTO rules (google_user_id,label_name,from_contains,is_active,
                                        mark_as_read,keep_in_inbox,star_email,created_by,created_at,updated_at)
                                    VALUES (%s,%s,%s,TRUE,FALSE,FALSE,FALSE,'ai',%s,%s)
                                """, (google_user_id, label, _domain, _now2, _now2))
                                conn2.commit()
                            conn2.close()
                        except Exception:
                            logger.exception("Auto-create rule failed in scheduler")

        skipped = max(0, total - rule_count - ai_count)
        _save_run(google_user_id, "run_labeler",
                  processed=total, rule_labeled=rule_count,
                  ai_labeled=ai_count, skipped=skipped)
        logger.info("[scheduler] run_labeler done for %s: processed=%d rule=%d ai=%d",
                    google_user_id, total, rule_count, ai_count)
    except Exception:
        logger.exception("[scheduler] run_labeler failed for %s", google_user_id)


def _job_learn_rules(google_user_id: str):
    """Run learn rules for one user — called by APScheduler."""
    logger.info("[scheduler] learn_rules starting for %s", google_user_id)
    try:
        from ai_labels import get_allowed_ai_labels
        from rule_learner import learn_rules_from_labeled_emails
        service = _get_gmail_service(google_user_id)
        allowed = get_allowed_ai_labels()
        created = learn_rules_from_labeled_emails(
            service=service, allowed_labels=allowed,
            max_per_label=100, min_domain_count=2,
            min_subject_token_count=999,  # effectively disabled
            google_user_id=google_user_id,
        )
        _save_run(google_user_id, "learn_rules", rules_created=created)
        logger.info("[scheduler] learn_rules done for %s: created=%d", google_user_id, created)
    except Exception:
        logger.exception("[scheduler] learn_rules failed for %s", google_user_id)


# ─────────────────────────────────────────────
# Schedule management
# ─────────────────────────────────────────────

def _rl_job_id(uid): return f"run_labeler_{uid}"
def _lr_job_id(uid): return f"learn_rules_{uid}"


def reschedule_user(google_user_id: str, cfg: dict):
    """Add/update/remove APScheduler jobs for one user based on their config."""
    rl = cfg.get("run_labeler", {})
    lr = cfg.get("learn_rules", {})

    # Run Labeler
    jid = _rl_job_id(google_user_id)
    if rl.get("enabled") and rl.get("interval_minutes", 0) > 0:
        mins = int(rl["interval_minutes"])
        if _scheduler.get_job(jid):
            _scheduler.reschedule_job(jid, trigger=IntervalTrigger(minutes=mins))
            logger.info("[scheduler] rescheduled %s every %dm", jid, mins)
        else:
            _scheduler.add_job(_job_run_labeler, IntervalTrigger(minutes=mins),
                               id=jid, args=[google_user_id],
                               replace_existing=True, misfire_grace_time=300)
            logger.info("[scheduler] added %s every %dm", jid, mins)
    else:
        if _scheduler.get_job(jid):
            _scheduler.remove_job(jid)
            logger.info("[scheduler] removed %s", jid)

    # Learn Rules
    jid = _lr_job_id(google_user_id)
    if lr.get("enabled") and lr.get("interval_minutes", 0) > 0:
        mins = int(lr["interval_minutes"])
        if _scheduler.get_job(jid):
            _scheduler.reschedule_job(jid, trigger=IntervalTrigger(minutes=mins))
            logger.info("[scheduler] rescheduled %s every %dm", jid, mins)
        else:
            _scheduler.add_job(_job_learn_rules, IntervalTrigger(minutes=mins),
                               id=jid, args=[google_user_id],
                               replace_existing=True, misfire_grace_time=300)
            logger.info("[scheduler] added %s every %dm", jid, mins)
    else:
        if _scheduler.get_job(jid):
            _scheduler.remove_job(jid)
            logger.info("[scheduler] removed %s", jid)


def init_scheduler():
    """Load all user schedules from DB and start APScheduler. Call once at app startup."""
    global _started
    if _started:
        return
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("SELECT google_user_id, schedule_config FROM user_settings WHERE schedule_config IS NOT NULL")
        rows = cur.fetchall()
        conn.close()
        for row in rows:
            uid = row["google_user_id"]
            raw = row["schedule_config"]
            if not raw:
                continue
            try:
                cfg = json.loads(raw)
                reschedule_user(uid, cfg)
            except Exception:
                logger.exception("[scheduler] Failed to load schedule for %s", uid)
        _scheduler.start()
        _started = True
        logger.info("[scheduler] APScheduler started with %d job(s)", len(_scheduler.get_jobs()))
    except Exception:
        logger.exception("[scheduler] Failed to start")
