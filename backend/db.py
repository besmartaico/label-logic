import os
import logging
from datetime import datetime
from urllib.parse import urlparse

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


# -----------------------------
# Connection / DSN helpers
# -----------------------------


def _looks_like_bad_internal_host(dsn: str) -> bool:
    """
    Railway internal DNS host can be present in some DATABASE_URLs depending on how
    variables were set/copied. If the app service is NOT attached to the Postgres
    service, 'postgres.railway.internal' will not resolve and the app will crash.
    """
    if not dsn:
        return False
    try:
        parsed = urlparse(dsn)
        host = (parsed.hostname or "").lower()
        return host.endswith(".railway.internal") or host == "postgres.railway.internal"
    except Exception:
        return False


def _first_env(*keys: str) -> str:
    for k in keys:
        v = os.environ.get(k)
        if v and str(v).strip():
            return str(v).strip()
    return ""


def _build_dsn_from_pg_env() -> str:
    """
    Build a postgres DSN from PG* env vars.

    Works well on Railway if you attached the Postgres service, since Railway often
    injects PGHOST/PGPORT/PGUSER/PGPASSWORD/PGDATABASE alongside DATABASE_URL.
    """
    host = _first_env("PGHOST", "POSTGRES_HOST", "DB_HOST")
    port = _first_env("PGPORT", "POSTGRES_PORT", "DB_PORT") or "5432"
    user = _first_env("PGUSER", "POSTGRES_USER", "DB_USER")
    password = _first_env("PGPASSWORD", "POSTGRES_PASSWORD", "DB_PASSWORD")
    dbname = _first_env("PGDATABASE", "POSTGRES_DB", "DB_NAME")

    if not all([host, port, user, password, dbname]):
        return ""

    # psycopg2 accepts space-separated dsn
    return f"host={host} port={port} dbname={dbname} user={user} password={password}"


def _choose_best_dsn() -> str:
    """
    Choose the best DSN in this priority order:

    1) Any explicit PUBLIC db url env var (most reliable across services/networks)
    2) DATABASE_URL (Railway standard)
    3) PG* env vars (Railway commonly provides)
    """
    # If you create one of these in Railway Variables, it will be used first.
    dsn_public = _first_env(
        "DATABASE_URL_PUBLIC",
        "DATABASE_PUBLIC_URL",
        "POSTGRES_URL_PUBLIC",
        "POSTGRES_PUBLIC_URL",
    )
    if dsn_public:
        return dsn_public

    dsn = _first_env("DATABASE_URL", "POSTGRES_URL")
    if dsn:
        return dsn

    dsn_from_parts = _build_dsn_from_pg_env()
    if dsn_from_parts:
        return dsn_from_parts

    return ""


def get_db_connection():
    """
    Returns a psycopg2 connection to Postgres.

    Expected env vars on Railway:
      - Prefer: DATABASE_URL_PUBLIC (if you set it) / DATABASE_PUBLIC_URL
      - Else:   DATABASE_URL (Railway Postgres provides this when service is connected)
      - Else:   PGHOST/PGPORT/PGUSER/PGPASSWORD/PGDATABASE (often present on Railway)

    SSL:
      - PGSSLMODE default: require
      - For local dev you can set: PGSSLMODE=disable
    """
    dsn = _choose_best_dsn()
    if not dsn:
        raise RuntimeError(
            "No Postgres connection info found. Set DATABASE_URL (Railway) or "
            "DATABASE_URL_PUBLIC / PGHOST+PGPORT+PGUSER+PGPASSWORD+PGDATABASE."
        )

    sslmode = os.environ.get("PGSSLMODE", "require")
    connect_timeout = int(os.environ.get("PGCONNECT_TIMEOUT", "10"))

    # If DATABASE_URL is pointing at an internal Railway host, it may fail DNS
    # when the Postgres service isn't attached to this app.
    # We try to fall back to a public DSN or PG* env vars automatically.
    if _looks_like_bad_internal_host(dsn):
        logger.warning(
            "DATABASE_URL appears to use a Railway internal host (%s). "
            "Attempting fallback to PUBLIC url or PG* env vars.",
            dsn,
        )

        fallback = _first_env(
            "DATABASE_URL_PUBLIC",
            "DATABASE_PUBLIC_URL",
            "POSTGRES_URL_PUBLIC",
            "POSTGRES_PUBLIC_URL",
        )
        if not fallback:
            fallback = _build_dsn_from_pg_env()

        if fallback:
            dsn = fallback
        else:
            # Provide a very explicit error so you immediately know what to change in Railway.
            raise RuntimeError(
                "DATABASE_URL points to 'postgres.railway.internal' but no PUBLIC url or PG* env vars "
                "are available to fall back to. In Railway, connect your app service to the Postgres "
                "service (so DATABASE_URL is injected correctly) OR set DATABASE_URL_PUBLIC."
            )

    try:
        conn = psycopg2.connect(
            dsn,
            sslmode=sslmode,
            connect_timeout=connect_timeout,
            connection_factory=_DictConnection,
        )
        return conn
    except psycopg2.OperationalError as e:
        # Add extra context for the most common Railway failure mode
        msg = str(e)
        if "could not translate host name" in msg and "railway.internal" in msg:
            raise psycopg2.OperationalError(
                msg
                + "\n\nLikely cause: DATABASE_URL is set to an internal Railway hostname but your app "
                  "service is not connected to the Postgres service. Fix: attach the Postgres service "
                  "to this app in Railway OR set DATABASE_URL_PUBLIC to a public connection string."
            )
        raise


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
