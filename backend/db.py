import os
import sqlite3
import logging
from datetime import datetime

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "label_logic.db")

logger = logging.getLogger(__name__)


def get_db_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


# -----------------------------
# Table creation / migrations
# -----------------------------


def ensure_rules_has_mark_as_read(cur):
    cur.execute("PRAGMA table_info(rules);")
    cols = [row[1] for row in cur.fetchall()]
    if "mark_as_read" not in cols:
        cur.execute(
            "ALTER TABLE rules ADD COLUMN mark_as_read INTEGER NOT NULL DEFAULT 0;"
        )


def ensure_labeled_emails_has_source(cur):
    cur.execute("PRAGMA table_info(labeled_emails);")
    cols = [row[1] for row in cur.fetchall()]
    if "source" not in cols:
        cur.execute("ALTER TABLE labeled_emails ADD COLUMN source TEXT;")


def ensure_google_accounts_table(cur):
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS google_accounts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            google_user_id TEXT UNIQUE,
            email TEXT,
            credentials_json TEXT,
            created_at TEXT,
            updated_at TEXT
        );
        """
    )


def init_db():
    conn = get_db_connection()
    cur = conn.cursor()

    # Labeled emails
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS labeled_emails (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            gmail_id TEXT UNIQUE,
            thread_id TEXT,
            sender TEXT,
            subject TEXT,
            snippet TEXT,
            applied_label TEXT,
            is_ai_labeled INTEGER DEFAULT 0,
            source TEXT,
            created_at TEXT
        );
        """
    )

    # Rules
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS rules (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            label_name TEXT NOT NULL,
            from_contains TEXT,
            subject_contains TEXT,
            body_contains TEXT,
            is_active INTEGER NOT NULL DEFAULT 1,
            mark_as_read INTEGER NOT NULL DEFAULT 0,
            created_at TEXT,
            updated_at TEXT
        );
        """
    )

    # AI suggestions
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS ai_label_suggestions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            gmail_id TEXT,
            suggested_label TEXT,
            confidence REAL,
            accepted INTEGER DEFAULT 1,
            created_at TEXT
        );
        """
    )

    ensure_google_accounts_table(cur)
    ensure_rules_has_mark_as_read(cur)
    ensure_labeled_emails_has_source(cur)

    conn.commit()
    conn.close()


# -----------------------------
# Google credential helpers
# -----------------------------


def save_credentials(google_user_id: str, email: str, creds):
    """
    Store or update credentials JSON for a Google user.
    """
    conn = get_db_connection()
    cur = conn.cursor()
    now = datetime.utcnow().isoformat(timespec="seconds")
    creds_json = creds.to_json()

    cur.execute(
        """
        INSERT INTO google_accounts
        (google_user_id, email, credentials_json, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?)
        ON CONFLICT(google_user_id) DO UPDATE SET
            email = excluded.email,
            credentials_json = excluded.credentials_json,
            updated_at = excluded.updated_at;
        """,
        (google_user_id, email, creds_json, now, now),
    )
    conn.commit()
    conn.close()


def load_credentials(google_user_id: str):
    """
    Load stored credential JSON for the given Google user id.
    Returns a dict or None.
    """
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute(
        "SELECT credentials_json FROM google_accounts WHERE google_user_id = ?;",
        (google_user_id,),
    )
    row = cur.fetchone()
    conn.close()
    if not row:
        return None
    return row["credentials_json"]


# -----------------------------
# Labeled email + AI suggestion helpers
# -----------------------------


def record_labeled_email(
    gmail_id,
    thread_id,
    sender,
    subject,
    snippet,
    label,
    is_ai_labeled=False,
    source=None,
):
    conn = get_db_connection()
    cur = conn.cursor()
    now = datetime.utcnow().isoformat(timespec="seconds")

    cur.execute(
        """
        INSERT INTO labeled_emails (
            gmail_id, thread_id, sender, subject, snippet,
            applied_label, is_ai_labeled, source, created_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(gmail_id) DO UPDATE SET
            thread_id = excluded.thread_id,
            sender = excluded.sender,
            subject = excluded.subject,
            snippet = excluded.snippet,
            applied_label = excluded.applied_label,
            is_ai_labeled = excluded.is_ai_labeled,
            source = excluded.source;
        """,
        (
            gmail_id,
            thread_id,
            sender,
            subject,
            snippet,
            label,
            1 if is_ai_labeled else 0,
            source,
            now,
        ),
    )

    conn.commit()
    conn.close()


def record_ai_suggestion(gmail_id, label, confidence):
    conn = get_db_connection()
    cur = conn.cursor()
    now = datetime.utcnow().isoformat(timespec="seconds")

    cur.execute(
        """
        INSERT INTO ai_label_suggestions (gmail_id, suggested_label, confidence, accepted, created_at)
        VALUES (?, ?, ?, ?, ?);
        """,
        (gmail_id, label, confidence, 1, now),
    )

    conn.commit()
    conn.close()


def extract_domain_from_sender(sender):
    """
    Extract domain from an email address in a 'From' header.
    """
    import re

    if not sender:
        return None
    m = re.search(r"@([A-Za-z0-9._-]+)", sender)
    if not m:
        return None
    domain = m.group(1).lower()
    if "." not in domain:
        return None
    return domain
