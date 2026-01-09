import os
import re
import sqlite3
import base64
import json
import logging
from datetime import datetime

from flask import (
    Flask,
    jsonify,
    redirect,
    render_template,
    request,
    url_for,
    session,
)

from dotenv import load_dotenv

# Gmail / Google API imports
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import Flow
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError
from google.oauth2 import id_token
from google.auth.transport import requests as google_requests
from google.auth.transport.requests import Request as GoogleAuthRequest

# OpenAI (Python SDK 1.x)
from openai import OpenAI

# -------------------------------------------------
# Config
# -------------------------------------------------

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "label_logic.db")

# Load environment variables from .env (if present)
load_dotenv()

# Logging configuration
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s - %(message)s",
)
logger = logging.getLogger(__name__)

# Scopes
GMAIL_SCOPES = ["https://www.googleapis.com/auth/gmail.modify"]
OIDC_SCOPES = ["openid", "https://www.googleapis.com/auth/userinfo.email"]
ALL_SCOPES = GMAIL_SCOPES + OIDC_SCOPES

# Redirect URI for OAuth (must match what you configure in Google Cloud)
GOOGLE_OAUTH_REDIRECT_URI = os.environ.get(
    "GOOGLE_OAUTH_REDIRECT_URI", "http://localhost:5000/oauth2callback"
)

# Flask secret key (for sessions)
SECRET_KEY = os.environ.get("FLASK_SECRET_KEY", "dev-secret-change-me")

# OpenAI client
OPENAI_API_KEY = os.environ.get("OPENAI_API_KEY", "")
openai_client = OpenAI(api_key=OPENAI_API_KEY) if OPENAI_API_KEY else None

# Backend behavior flags (from .env)
def _env_bool(key: str, default: str = "true") -> bool:
    return os.environ.get(key, default).strip().lower() in ("1", "true", "yes", "on")


ARCHIVE_RULE_LABELED = _env_bool("ARCHIVE_RULE_LABELED", "true")
ARCHIVE_AI_LABELED = _env_bool("ARCHIVE_AI_LABELED", "true")

try:
    MAX_EMAILS_PER_RUN = int(os.environ.get("MAX_EMAILS_PER_RUN", "50"))
    if MAX_EMAILS_PER_RUN <= 0:
        MAX_EMAILS_PER_RUN = 50
except ValueError:
    MAX_EMAILS_PER_RUN = 50

logger.info(
    "Config: ARCHIVE_RULE_LABELED=%s ARCHIVE_AI_LABELED=%s MAX_EMAILS_PER_RUN=%d",
    ARCHIVE_RULE_LABELED,
    ARCHIVE_AI_LABELED,
    MAX_EMAILS_PER_RUN,
)

# Core LL labels we always want available
DEFAULT_LL_LABELS = [
    "@LL-Blackhole",
    "@LL-Finance",
    "@LL-Purchases",
    "@LL-Security",
    "@LL-Soliciting",
    "@LL-News",
    "@LL-Travel",
    "@LL-Threat",
]

# Base AI labels start with the defaults; any additional @LL- labels
# added as rule labels will be merged in dynamically.
BASE_AI_LABELS = DEFAULT_LL_LABELS[:]  # copy

# -------------------------------------------------
# Flask app
# -------------------------------------------------

app = Flask(__name__)
app.secret_key = SECRET_KEY

# -------------------------------------------------
# DB helpers & initialization
# -------------------------------------------------


def get_db_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def ensure_rules_has_mark_as_read(cur):
    """
    Lightweight migration: if rules table exists but lacks mark_as_read,
    add it with a default of 0.
    """
    cur.execute("PRAGMA table_info(rules);")
    cols = [row[1] for row in cur.fetchall()]
    if "mark_as_read" not in cols:
        cur.execute(
            "ALTER TABLE rules ADD COLUMN mark_as_read INTEGER NOT NULL DEFAULT 0;"
        )


def ensure_labeled_emails_has_source(cur):
    """
    Lightweight migration: if labeled_emails table exists but lacks source,
    add it as TEXT.
    """
    cur.execute("PRAGMA table_info(labeled_emails);")
    cols = [row[1] for row in cur.fetchall()]
    if "source" not in cols:
        cur.execute("ALTER TABLE labeled_emails ADD COLUMN source TEXT;")


def ensure_google_accounts_table(cur):
    """
    Table to store per-user Google OAuth credentials for SaaS usage.
    """
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
    """
    Ensure required tables exist and run simple migrations.
    """
    conn = get_db_connection()
    cur = conn.cursor()

    # Stores applied labels for tracking
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

    # Rules table
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

    # AI suggestions table
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

    # New: google_accounts for per-user tokens
    ensure_google_accounts_table(cur)

    # Migrations
    ensure_rules_has_mark_as_read(cur)
    ensure_labeled_emails_has_source(cur)

    conn.commit()
    conn.close()


init_db()

# -------------------------------------------------
# Dynamic AI label list
# -------------------------------------------------


def get_dynamic_ll_labels_from_db():
    """
    Look at existing rules and pull any label_name that starts with @LL-.
    These will be merged into the AI's allowed label list.
    """
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute(
            "SELECT DISTINCT label_name FROM rules WHERE label_name LIKE '@LL-%';"
        )
        rows = cur.fetchall()
        conn.close()
        return [r["label_name"] for r in rows if r["label_name"]]
    except Exception:
        logger.exception("Failed to load dynamic LL labels from rules")
        return []


def get_allowed_ai_labels():
    """
    Returns the full set of labels the AI is allowed to choose from:
      - All DEFAULT_LL_LABELS
      - Plus any additional @LL- labels that exist in rules
      - Plus the special 'None' option
    """
    labels = set(BASE_AI_LABELS)
    dynamic = get_dynamic_ll_labels_from_db()
    for lbl in dynamic:
        labels.add(lbl)

    labels_list = sorted(labels)
    labels_list.append("None")  # special no-label option
    return labels_list


# -------------------------------------------------
# Google OAuth helpers (multi-user)
# -------------------------------------------------


def save_credentials(google_user_id: str, email: str, creds: Credentials):
    """
    Store or update credentials for a Google user.
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


def load_credentials(google_user_id: str) -> Credentials | None:
    """
    Load stored credentials for the given Google user id.
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
    data = json.loads(row["credentials_json"])
    return Credentials.from_authorized_user_info(data, GMAIL_SCOPES)


def is_probably_valid_label_name(name: str) -> bool:
    """
    Basic sanity checks before we ask Gmail to create/use a label.
    """
    if not name:
        return False
    name = name.strip()
    if not name:
        return False
    if len(name) > 225:
        return False
    if name.startswith("^"):
        return False
    return True


def get_gmail_service_for_current_user():
    """
    Build a Gmail service client for the currently logged-in Google user.
    """
    google_user_id = session.get("google_user_id")
    if not google_user_id:
        raise RuntimeError("Not logged in with Google")

    creds = load_credentials(google_user_id)
    if not creds:
        raise RuntimeError("No stored credentials for this user")

    if not creds.valid:
        if creds.expired and creds.refresh_token:
            logger.info("Refreshing Gmail credentials for user %s", google_user_id)
            creds.refresh(GoogleAuthRequest())
            save_credentials(google_user_id, session.get("email", ""), creds)
        else:
            raise RuntimeError("Credentials invalid and no refresh token")

    return build("gmail", "v1", credentials=creds)


def get_or_create_gmail_label(service, label_name):
    """
    Return the Gmail label ID for label_name, creating it if needed.
    """
    if not is_probably_valid_label_name(label_name):
        logger.warning("Skipping invalid label name %r (pre-validation)", label_name)
        return None

    try:
        resp = service.users().labels().list(userId="me").execute()
    except HttpError as e:
        logger.exception("Failed to list Gmail labels: %s", e)
        return None

    for lbl in resp.get("labels", []):
        if lbl.get("name") == label_name:
            return lbl.get("id")

    logger.info("Creating new Gmail label: %s", label_name)
    try:
        new_label = (
            service.users()
            .labels()
            .create(
                userId="me",
                body={
                    "name": label_name,
                    "labelListVisibility": "labelShow",
                    "messageListVisibility": "show",
                },
            )
            .execute()
        )
        return new_label.get("id")
    except HttpError as e:
        logger.exception("Failed to create Gmail label %r: %s", label_name, e)
        return None


def get_label_id_by_name(service, label_name: str):
    """
    Return the Gmail label ID for an existing label name, or None.
    Does NOT create labels.
    """
    try:
        resp = service.users().labels().list(userId="me").execute()
    except HttpError as e:
        logger.exception("Failed to list Gmail labels while resolving name=%r", label_name)
        return None

    for lbl in resp.get("labels", []):
        if lbl.get("name") == label_name:
            return lbl.get("id")
    return None


def apply_label_to_message(
    service,
    gmail_id,
    label_name,
    remove_from_inbox=False,
    mark_as_read=False,
):
    """
    Apply a label to a Gmail message by ID.
    """
    label_id = get_or_create_gmail_label(service, label_name)
    if not label_id:
        logger.warning("Could not get/create label_id for '%s'", label_name)
        return

    body = {"addLabelIds": [label_id]}
    remove_ids = []

    if remove_from_inbox:
        remove_ids.append("INBOX")
    if mark_as_read:
        remove_ids.append("UNREAD")

    if remove_ids:
        body["removeLabelIds"] = remove_ids

    service.users().messages().modify(
        userId="me", id=gmail_id, body=body
    ).execute()


def extract_email_fields(message):
    """
    Given a Gmail message resource (format='full'),
    extract sender, subject, snippet, simple text body.
    """
    headers = message.get("payload", {}).get("headers", [])
    header_map = {h["name"].lower(): h["value"] for h in headers}

    sender = header_map.get("from", "")
    subject = header_map.get("subject", "")
    snippet = message.get("snippet", "")

    body_text = ""

    def walk_parts(part):
        nonlocal body_text
        if "parts" in part:
            for p in part["parts"]:
                walk_parts(p)
        else:
            mime_type = part.get("mimeType", "")
            data = part.get("body", {}).get("data")
            if data and mime_type.startswith("text/plain"):
                try:
                    body_text += base64.urlsafe_b64decode(data).decode(
                        "utf-8", errors="ignore"
                    )
                except Exception:
                    logger.exception("Failed to decode email body part")

    payload = message.get("payload", {})
    walk_parts(payload)

    if not body_text:
        body_text = snippet or ""

    return sender, subject, snippet, body_text


def email_matches_rule(sender, subject, body, rule):
    """
    OR-based matching: from / subject / body.
    """
    s_from = (sender or "").lower()
    s_subject = (subject or "").lower()
    s_body = (body or "").lower()

    from_term = (rule["from_contains"] or "").lower().strip()
    subj_term = (rule["subject_contains"] or "").lower().strip()
    body_term = (rule["body_contains"] or "").lower().strip()

    if from_term and from_term in s_from:
        return True
    if subj_term and subj_term in s_subject:
        return True
    if body_term and body_term in s_body:
        return True

    return False


def ai_suggest_label(sender, subject, body):
    """
    Use OpenAI Chat Completions to suggest a label
    from the *dynamic* allowed list.
    """
    if not openai_client or not OPENAI_API_KEY:
        return None, 0.0

    allowed_labels = get_allowed_ai_labels()
    label_map = {lbl.lower(): lbl for lbl in allowed_labels}
    label_list = ", ".join(allowed_labels)

    system_prompt = (
        "You are an email classifier for a personal inbox. "
        "You must choose exactly one label from the allowed list, "
        "or 'None' if the email does not clearly fit any category."
    )

    user_prompt = f"""
Allowed labels:
{label_list}

Sender: {sender}
Subject: {subject}
Body (truncated):
{body[:1200]}

Respond with only the label text (exactly as in the list) or 'None'.
"""

    try:
        resp = openai_client.chat.completions.create(
            model="gpt-4o",
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
            max_tokens=20,
            temperature=0,
        )
        raw = (resp.choices[0].message.content or "").strip()
        norm = label_map.get(raw.lower())
        if not norm or norm == "None":
            return None, 0.0

        confidence = 0.75  # placeholder
        return norm, confidence
    except Exception:
        logger.exception("Error from OpenAI while suggesting label")
        return None, 0.0


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
    if not sender:
        return None
    m = re.search(r"@([A-Za-z0-9._-]+)", sender)
    if not m:
        return None
    domain = m.group(1).lower()
    if "." not in domain:
        return None
    return domain


# -------------------------------------------------
# Basic pages & status
# -------------------------------------------------


@app.route("/")
def index():
    if "google_user_id" not in session:
        return redirect(url_for("auth_google"))
    return redirect(url_for("rules_page"))


@app.route("/health")
def health():
    return jsonify({"status": "ok"})


@app.route("/ai-status")
def ai_status():
    return jsonify(
        {
            "has_api_key": bool(OPENAI_API_KEY),
            "allowed_labels": get_allowed_ai_labels(),
        }
    )


# -------------------------------------------------
# Google OAuth routes
# -------------------------------------------------


@app.route("/auth/google")
def auth_google():
    flow = Flow.from_client_secrets_file(
        os.path.join(BASE_DIR, "credentials.json"),
        scopes=ALL_SCOPES,
        redirect_uri=GOOGLE_OAUTH_REDIRECT_URI,
    )
    auth_url, state = flow.authorization_url(
        access_type="offline",
        include_granted_scopes="true",
        prompt="consent",
    )
    session["state"] = state
    return redirect(auth_url)


@app.route("/oauth2callback")
def oauth2callback():
    state = session.get("state")
    if not state:
        return jsonify({"error": "Missing OAuth state"}), 400

    flow = Flow.from_client_secrets_file(
        os.path.join(BASE_DIR, "credentials.json"),
        scopes=ALL_SCOPES,
        state=state,
        redirect_uri=GOOGLE_OAUTH_REDIRECT_URI,
    )

    flow.fetch_token(authorization_response=request.url)
    creds = flow.credentials

    try:
        idinfo = id_token.verify_oauth2_token(
            creds.id_token,
            google_requests.Request(),
            creds.client_id,
        )
    except Exception:
        logger.exception("Failed to verify ID token")
        return jsonify({"error": "Failed to verify ID token"}), 400

    google_user_id = idinfo.get("sub")
    email = idinfo.get("email")

    if not google_user_id or not email:
        return jsonify({"error": "Missing user info from ID token"}), 400

    save_credentials(google_user_id, email, creds)

    session["google_user_id"] = google_user_id
    session["email"] = email

    logger.info("User logged in: %s (%s)", email, google_user_id)
    return redirect(url_for("rules_page"))


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("auth_google"))


# -------------------------------------------------
# Simple API: labeled emails count
# -------------------------------------------------


@app.route("/api/labeled-emails-count", methods=["GET"])
def api_labeled_emails_count():
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("SELECT COUNT(*) FROM labeled_emails;")
    row = cur.fetchone()
    conn.close()
    count = row[0] if row else 0
    return jsonify({"count": count, "status": "Fetched labeled emails"})


# -------------------------------------------------
# Rules GUI
# -------------------------------------------------


@app.route("/rules", methods=["GET"])
def rules_page():
    if "google_user_id" not in session:
        return redirect(url_for("auth_google"))
    return render_template("rules.html")


@app.route("/relabel", methods=["GET"])
def relabel_page():
    if "google_user_id" not in session:
        return redirect(url_for("auth_google"))
    return render_template("relabel.html")


def db_row_to_rule(row):
    return {
        "id": row["id"],
        "label_name": row["label_name"],
        "from_contains": row["from_contains"] or "",
        "subject_contains": row["subject_contains"] or "",
        "body_contains": row["body_contains"] or "",
        "is_active": bool(row["is_active"]),
        "mark_as_read": bool(row["mark_as_read"]),
    }


def load_active_rules():
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute(
        """
        SELECT * FROM rules
        WHERE is_active = 1
        ORDER BY id;
        """
    )
    rows = cur.fetchall()
    conn.close()
    return [db_row_to_rule(r) for r in rows]


def validate_rule_label_name(label_name: str):
    if not label_name:
        return False, "label_name is required"
    if not is_probably_valid_label_name(label_name):
        return False, "Label name is empty, too long, or otherwise invalid."
    return True, None


@app.route("/api/rules", methods=["GET"])
def api_get_rules():
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("SELECT * FROM rules ORDER BY id;")
    rows = cur.fetchall()
    conn.close()

    rules = [db_row_to_rule(r) for r in rows]
    return jsonify(rules)


@app.route("/api/rules", methods=["POST"])
def api_create_rule():
    data = request.get_json() or {}
    label_name = (data.get("label_name") or "").strip()
    from_contains = (data.get("from_contains") or "").strip()
    subject_contains = (data.get("subject_contains") or "").strip()
    body_contains = (data.get("body_contains") or "").strip()
    is_active = 1 if data.get("is_active", True) else 0
    mark_as_read = 1 if data.get("mark_as_read", False) else 0

    is_valid, error_msg = validate_rule_label_name(label_name)
    if not is_valid:
        return jsonify({"error": error_msg}), 400

    now = datetime.utcnow().isoformat(timespec="seconds")

    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute(
        """
        INSERT INTO rules
        (label_name, from_contains, subject_contains, body_contains,
         is_active, mark_as_read, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?);
        """,
        (
            label_name,
            from_contains,
            subject_contains,
            body_contains,
            is_active,
            mark_as_read,
            now,
            now,
        ),
    )
    new_id = cur.lastrowid
    conn.commit()
    conn.close()

    return (
        jsonify(
            {
                "id": new_id,
                "label_name": label_name,
                "from_contains": from_contains,
                "subject_contains": subject_contains,
                "body_contains": body_contains,
                "is_active": bool(is_active),
                "mark_as_read": bool(mark_as_read),
            }
        ),
        201,
    )


@app.route("/api/rules/<int:rule_id>", methods=["PUT"])
def api_update_rule(rule_id):
    data = request.get_json() or {}
    label_name = data.get("label_name")
    from_contains = data.get("from_contains")
    subject_contains = data.get("subject_contains")
    body_contains = data.get("body_contains")
    is_active = data.get("is_active")
    mark_as_read = data.get("mark_as_read")

    conn = get_db_connection()
    cur = conn.cursor()

    cur.execute("SELECT * FROM rules WHERE id = ?;", (rule_id,))
    row = cur.fetchone()
    if not row:
        conn.close()
        return jsonify({"error": "Rule not found"}), 404

    new_label_name = (label_name or row["label_name"]).strip()
    new_from = (
        (from_contains if from_contains is not None else row["from_contains"] or "")
        .strip()
    )
    new_subject = (
        (subject_contains if subject_contains is not None else row["subject_contains"] or "")
        .strip()
    )
    new_body = (
        (body_contains if body_contains is not None else row["body_contains"] or "")
        .strip()
    )
    new_is_active = 1 if (is_active if is_active is not None else row["is_active"]) else 0
    new_mark_as_read = (
        1 if (mark_as_read if mark_as_read is not None else row["mark_as_read"]) else 0
    )

    is_valid, error_msg = validate_rule_label_name(new_label_name)
    if not is_valid:
        conn.close()
        return jsonify({"error": error_msg}), 400

    now = datetime.utcnow().isoformat(timespec="seconds")

    cur.execute(
        """
        UPDATE rules
        SET label_name = ?,
            from_contains = ?,
            subject_contains = ?,
            body_contains = ?,
            is_active = ?,
            mark_as_read = ?,
            updated_at = ?
        WHERE id = ?;
        """,
        (
            new_label_name,
            new_from,
            new_subject,
            new_body,
            new_is_active,
            new_mark_as_read,
            now,
            rule_id,
        ),
    )
    conn.commit()
    conn.close()

    return jsonify(
        {
            "id": rule_id,
            "label_name": new_label_name,
            "from_contains": new_from,
            "subject_contains": new_subject,
            "body_contains": new_body,
            "is_active": bool(new_is_active),
            "mark_as_read": bool(new_mark_as_read),
        }
    )


@app.route("/api/rules/<int:rule_id>", methods=["DELETE"])
def api_delete_rule(rule_id):
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("DELETE FROM rules WHERE id = ?;", (rule_id,))
    conn.commit()
    conn.close()
    return jsonify({"status": "deleted"})


# -------------------------------------------------
# Gmail labels for UI (dropdown + unread table)
# -------------------------------------------------


@app.route("/api/gmail-labels", methods=["GET"])
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


@app.route("/api/labels", methods=["GET"])
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
            detail = (
                service.users()
                .labels()
                .get(userId="me", id=lbl["id"])
                .execute()
            )
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


@app.route("/api/labels/<label_id>/mark-read", methods=["POST"])
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
            {
                "status": "ok",
                "updated": 0,
                "message": "No unread messages in this label.",
            }
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


# -------------------------------------------------
# Run labeler – rules + AI
# -------------------------------------------------


@app.route("/run-labeler", methods=["POST"])
def run_labeler():
    try:
        service = get_gmail_service_for_current_user()
    except RuntimeError as e:
        return jsonify({"error": str(e)}), 401
    except Exception as e:
        logger.exception("Gmail auth failed in run_labeler")
        return jsonify({"error": f"Gmail auth failed: {e}"}), 500

    rules = load_active_rules()
    rule_count = 0
    ai_count = 0
    total = 0

    try:
        msg_list = (
            service.users()
            .messages()
            .list(
                userId="me",
                labelIds=["INBOX"],
                maxResults=MAX_EMAILS_PER_RUN,
            )
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
                    remove_from_inbox=ARCHIVE_RULE_LABELED,
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
                rule_count += 1
                break

        if not matched_label:
            label, conf = ai_suggest_label(sender, subject, body)
            if label:
                apply_label_to_message(
                    service,
                    gmail_id,
                    label,
                    remove_from_inbox=ARCHIVE_AI_LABELED,
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
                ai_count += 1

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
        }
    )


# -------------------------------------------------
# Learn from user labels
# -------------------------------------------------


@app.route("/learn-from-user-labels", methods=["POST"])
def learn_from_user_labels():
    try:
        service = get_gmail_service_for_current_user()
    except RuntimeError as e:
        return jsonify({"error": str(e)}), 401
    except Exception as e:
        logger.exception("Gmail auth failed in learn_from_user_labels")
        return jsonify({"error": f"Gmail auth failed: {e}"}), 500

    conn = get_db_connection()
    cur = conn.cursor()

    cur.execute("SELECT gmail_id FROM labeled_emails;")
    existing_ids = {row["gmail_id"] for row in cur.fetchall()}

    user_id = "me"
    label_list_resp = service.users().labels().list(userId=user_id).execute()
    labels = label_list_resp.get("labels", [])

    user_label_ids = [lbl["id"] for lbl in labels if lbl.get("type") == "user"]

    user_labeled_added = 0

    for lid in user_label_ids:
        try:
            msg_list = (
                service.users()
                .messages()
                .list(userId=user_id, labelIds=[lid], maxResults=50)
                .execute()
            )
        except HttpError:
            logger.exception("Error listing messages for label %s", lid)
            continue

        for m in msg_list.get("messages", []):
            gmail_id = m["id"]
            if gmail_id in existing_ids:
                continue

            try:
                full = (
                    service.users()
                    .messages()
                    .get(userId=user_id, id=gmail_id, format="full")
                    .execute()
                )
            except HttpError:
                logger.exception(
                    "Error fetching full message in learn_from_user_labels"
                )
                continue

            sender, subject, snippet, body = extract_email_fields(full)
            thread_id = full.get("threadId", "")

            lbl_name = None
            for lbl in labels:
                if lbl["id"] == lid:
                    lbl_name = lbl.get("name", "")
                    break
            if not lbl_name:
                continue

            record_labeled_email(
                gmail_id,
                thread_id,
                sender,
                subject,
                snippet,
                lbl_name,
                is_ai_labeled=False,
                source="user",
            )
            existing_ids.add(gmail_id)
            user_labeled_added += 1

    cur.execute(
        """
        SELECT sender, applied_label
        FROM labeled_emails
        WHERE source = 'user';
        """
    )
    rows = cur.fetchall()

    domain_counts = {}
    for row in rows:
        sender = row["sender"]
        label = row["applied_label"]
        domain = extract_domain_from_sender(sender)
        if not domain:
            continue
        key = (label, domain)
        domain_counts[key] = domain_counts.get(key, 0) + 1

    DOMAIN_THRESHOLD = 3
    rules_created = 0

    for (label, domain), cnt in domain_counts.items():
        if cnt < DOMAIN_THRESHOLD:
            continue

        cur.execute(
            """
            SELECT 1 FROM rules
            WHERE label_name = ?
              AND from_contains = ?
              AND is_active = 1
            LIMIT 1;
            """,
            (label, f"@{domain}"),
        )
        exists = cur.fetchone()
        if exists:
            continue

        now = datetime.utcnow().isoformat(timespec="seconds")
        cur.execute(
            """
            INSERT INTO rules
            (label_name, from_contains, subject_contains, body_contains,
             is_active, mark_as_read, created_at, updated_at)
            VALUES (?, ?, '', '', 1, 0, ?, ?);
            """,
            (label, f"@{domain}", now, now),
        )
        rules_created += 1

    conn.commit()
    conn.close()

    logger.info(
        "learn_from_user_labels finished: user_labeled_added=%d rules_created=%d",
        user_labeled_added,
        rules_created,
    )

    return jsonify(
        {
            "status": "ok",
            "user_labeled_added": user_labeled_added,
            "rules_created": rules_created,
        }
    )


# -------------------------------------------------
# Init default LL labels
# -------------------------------------------------


@app.route("/init-default-labels", methods=["GET", "POST"])
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

    return jsonify(
        {
            "status": "ok",
            "count": len(ensured),
            "ensured_labels": ensured,
        }
    )


# -------------------------------------------------
# Relabel API – move all messages from one label to another
# -------------------------------------------------


@app.route("/api/relabel", methods=["POST"])
def api_relabel():
    """
    Move all messages from one label to another:
      - Add target label
      - Remove source label
    Body JSON:
      {
        "source_label": "Old",
        "target_label": "@LL-New"
      }
    """
    data = request.get_json() or {}
    source_label = (data.get("source_label") or "").strip()
    target_label = (data.get("target_label") or "").strip()

    if not source_label or not target_label:
        return jsonify({"error": "source_label and target_label are required"}), 400
    if source_label == target_label:
        return jsonify({"error": "source_label and target_label must be different"}), 400

    try:
        service = get_gmail_service_for_current_user()
    except RuntimeError as e:
        return jsonify({"error": str(e)}), 401
    except Exception as e:
        logger.exception("Gmail auth failed in api_relabel")
        return jsonify({"error": f"Gmail auth failed: {e}"}), 500

    source_id = get_label_id_by_name(service, source_label)
    if not source_id:
        return jsonify({"error": f"Source label not found: {source_label}"}), 400

    target_id = get_or_create_gmail_label(service, target_label)
    if not target_id:
        return jsonify({"error": f"Could not get/create target label: {target_label}"}), 500

    user_id = "me"
    total_updated = 0
    page_token = None

    try:
        while True:
            resp = (
                service.users()
                .messages()
                .list(
                    userId=user_id,
                    labelIds=[source_id],
                    pageToken=page_token,
                    maxResults=500,
                )
                .execute()
            )
            msgs = resp.get("messages", [])
            if not msgs:
                break

            ids = [m["id"] for m in msgs]

            service.users().messages().batchModify(
                userId=user_id,
                body={
                    "ids": ids,
                    "addLabelIds": [target_id],
                    "removeLabelIds": [source_id],
                },
            ).execute()

            total_updated += len(ids)
            page_token = resp.get("nextPageToken")
            if not page_token:
                break

    except HttpError as e:
        logger.exception("Error relabeling messages from %s to %s", source_label, target_label)
        return jsonify({"error": f"Gmail API error: {e}"}), 500

    return jsonify(
        {
            "status": "ok",
            "source_label": source_label,
            "target_label": target_label,
            "updated": total_updated,
        }
    )


# -------------------------------------------------
# Main
# -------------------------------------------------

if __name__ == "__main__":
    logger.info("Starting app with redirect URI: %s", GOOGLE_OAUTH_REDIRECT_URI)
    app.run(host="0.0.0.0", port=5000, debug=True)
