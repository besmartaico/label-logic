import os
import logging
from datetime import datetime

import psycopg2
from psycopg2.extras import RealDictCursor

logger = logging.getLogger(__name__)


class _DictConnection(psycopg2.extensions.connection):
    """
    Connection that defaults to dict rows (RealDictCursor) so existing code that
    expects row["col"] keeps working.
    """

    def cursor(self, *args, **kwargs):
        kwargs.setdefault("cursor_factory", RealDictCursor)
        return super().cursor(*args, **kwargs)


def get_db_connection():
    """
    Returns a psycopg2 connection to Postgres using DATABASE_URL.

    Required env var:
      - DATABASE_URL (Railway Postgres provides this)

    Optional:
      - PGSSLMODE (default: require). For local dev you can set: PGSSLMODE=disable
    """
    dsn = os.environ.get("DATABASE_URL", "").strip()
    if not dsn:
        raise RuntimeError("Missing DATABASE_URL env var (Postgres connection string).")

    sslmode = os.environ.get("PGSSLMODE", "require")

    conn = psycopg2.connect(
        dsn,
        sslmode=sslmode,
        connection_factory=_DictConnection,
    )
    return conn


# -----------------------------
# Table creation / migrations
# -----------------------------


def init_db():
    """
    Create tables if they don't exist.
    Safe to call at startup.
    """
    conn = get_db_connection()
    cur = conn.cursor()

    # google_accounts: stores OAuth creds per Google user
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS google_accounts (
            id BIGSERIAL PRIMARY KEY,
            google_user_id TEXT UNIQUE NOT NULL,
            email TEXT,
            credentials_json TEXT,
            created_at TEXT,
            updated_at TEXT
        );
        """
    )

    # labeled_emails: tracks what we labeled and why
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS labeled_emails (
            id BIGSERIAL PRIMARY KEY,
            gmail_id TEXT UNIQUE NOT NULL,
            thread_id TEXT,
            sender TEXT,
            subject TEXT,
            snippet TEXT,
            applied_label TEXT,
            is_ai_labeled BOOLEAN DEFAULT FALSE,
            source TEXT,
            created_at TEXT
        );
        """
    )

    # rules: user-created matching rules
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS rules (
            id BIGSERIAL PRIMARY KEY,
            label_name TEXT NOT NULL,
            from_contains TEXT,
            subject_contains TEXT,
            body_contains TEXT,
            is_active BOOLEAN NOT NULL DEFAULT TRUE,
            mark_as_read BOOLEAN NOT NULL DEFAULT FALSE,
            created_at TEXT,
            updated_at TEXT
        );
        """
    )

    # ai_label_suggestions: optional logging of AI suggestions
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS ai_label_suggestions (
            id BIGSERIAL PRIMARY KEY,
            gmail_id TEXT,
            suggested_label TEXT,
            confidence REAL,
            accepted BOOLEAN DEFAULT TRUE,
            created_at TEXT
        );
        """
    )

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
        VALUES
            (%s, %s, %s, %s, %s)
        ON CONFLICT (google_user_id) DO UPDATE SET
            email = EXCLUDED.email,
            credentials_json = EXCLUDED.credentials_json,
            updated_at = EXCLUDED.updated_at;
        """,
        (google_user_id, email, creds_json, now, now),
    )
    conn.commit()
    conn.close()


def load_credentials(google_user_id: str):
    """
    Load stored credential JSON for the given Google user id.
    Returns JSON string or None.
    """
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute(
        "SELECT credentials_json FROM google_accounts WHERE google_user_id = %s;",
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
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
        ON CONFLICT (gmail_id) DO UPDATE SET
            thread_id = EXCLUDED.thread_id,
            sender = EXCLUDED.sender,
            subject = EXCLUDED.subject,
            snippet = EXCLUDED.snippet,
            applied_label = EXCLUDED.applied_label,
            is_ai_labeled = EXCLUDED.is_ai_labeled,
            source = EXCLUDED.source;
        """,
        (
            gmail_id,
            thread_id,
            sender,
            subject,
            snippet,
            label,
            bool(is_ai_labeled),
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
        INSERT INTO ai_label_suggestions
            (gmail_id, suggested_label, confidence, accepted, created_at)
        VALUES
            (%s, %s, %s, %s, %s);
        """,
        (gmail_id, label, confidence, True, now),
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
