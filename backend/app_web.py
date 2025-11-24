import os
import re
import sqlite3
import base64
import json
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

# Gmail / Google auth imports
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import Flow
import google.oauth2.id_token as google_id_token
import google.auth.transport.requests as google_requests
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError

# OpenAI (Python SDK 1.x)
from openai import OpenAI

# -------------------------------------------------
# Config
# -------------------------------------------------

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "label_logic.db")

load_dotenv()

# Gmail scopes – allow reading, labeling, marking read
SCOPES = ["https://www.googleapis.com/auth/gmail.modify"]

# Load web OAuth credentials (created in Google Cloud Console)
WEB_CREDS_PATH = os.path.join(BASE_DIR, "web_credentials.json")
with open(WEB_CREDS_PATH, "r") as f:
    web_creds = json.load(f)["web"]

GOOGLE_CLIENT_ID = web_creds["client_id"]
GOOGLE_CLIENT_SECRET = web_creds["client_secret"]
# IMPORTANT: this must match your OAuth client in Google Cloud
GOOGLE_REDIRECT_URI = "http://localhost:5000/oauth2callback"

# OpenAI client
OPENAI_API_KEY = os.environ.get("OPENAI_API_KEY", "")
openai_client = OpenAI(api_key=OPENAI_API_KEY) if OPENAI_API_KEY else None

# Fixed AI label set
AI_LABELS = [
    "Priority",
    "Finance",
    "Promotions",
    "Newsletters",
    "Work",
    "Personal",
    "Orders",
    "Security",
    "Travel",
    "Spam",
    "Junk",
    "Threat",
    "None",  # special "no label" option
]
AI_LABEL_MAP = {lbl.lower(): lbl for lbl in AI_LABELS}

# Flask app
app = Flask(__name__)
app.secret_key = os.getenv("FLASK_SECRET_KEY", "dev-change-me")  # set real secret in prod

# -------------------------------------------------
# DB helpers & init
# -------------------------------------------------


def get_db_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


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


def ensure_user_id_columns(cur):
    # rules.user_id
    cur.execute("PRAGMA table_info(rules);")
    cols = [row[1] for row in cur.fetchall()]
    if "user_id" not in cols:
        cur.execute("ALTER TABLE rules ADD COLUMN user_id INTEGER;")

    # labeled_emails.user_id
    cur.execute("PRAGMA table_info(labeled_emails);")
    cols = [row[1] for row in cur.fetchall()]
    if "user_id" not in cols:
        cur.execute("ALTER TABLE labeled_emails ADD COLUMN user_id INTEGER;")


def init_db():
    conn = get_db_connection()
    cur = conn.cursor()

    # Users table – one row per Google account
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            google_user_id TEXT UNIQUE,
            email TEXT,
            access_token TEXT,
            refresh_token TEXT,
            token_expiry TEXT,
            created_at TEXT
        );
        """
    )

    # Labeled emails table (per user)
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
            created_at TEXT,
            user_id INTEGER
        );
        """
    )

    # Rules table (per user)
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS rules (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
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

    # Optional – AI suggestion log (global)
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

    # Migrations (safe to run repeatedly)
    ensure_rules_has_mark_as_read(cur)
    ensure_labeled_emails_has_source(cur)
    ensure_user_id_columns(cur)

    conn.commit()
    conn.close()


init_db()

# -------------------------------------------------
# Auth helpers
# -------------------------------------------------


def get_current_user_id():
    return session.get("user_id")


def get_gmail_service_for_user(user_id: int):
    """Build a Gmail API client using tokens stored for this user."""
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE id = ?;", (user_id,))
    row = cur.fetchone()
    conn.close()
    if not row:
        raise RuntimeError("User not found")

    creds = Credentials(
        token=row["access_token"],
        refresh_token=row["refresh_token"],
        token_uri="https://oauth2.googleapis.com/token",
        client_id=GOOGLE_CLIENT_ID,
        client_secret=GOOGLE_CLIENT_SECRET,
        scopes=SCOPES,
    )

    if not creds.valid and creds.refresh_token:
        req = google_requests.Request()
        creds.refresh(req)

        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute(
            """
            UPDATE users
            SET access_token = ?, token_expiry = ?
            WHERE id = ?;
            """,
            (
                creds.token,
                creds.expiry.isoformat() if creds.expiry else None,
                user_id,
            ),
        )
        conn.commit()
        conn.close()

    return build("gmail", "v1", credentials=creds)


# -------------------------------------------------
# Email helpers
# -------------------------------------------------


def get_or_create_gmail_label(service, label_name):
    resp = service.users().labels().list(userId="me").execute()
    for lbl in resp.get("labels", []):
        if lbl["name"] == label_name:
            return lbl["id"]

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
    return new_label["id"]


def apply_label_to_message(
    service,
    gmail_id,
    label_name,
    remove_from_inbox=False,
    mark_as_read=False,
):
    label_id = get_or_create_gmail_label(service, label_name)
    if not label_id:
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
                    pass

    payload = message.get("payload", {})
    walk_parts(payload)

    if not body_text:
        body_text = snippet or ""

    return sender, subject, snippet, body_text


def email_matches_rule(sender, subject, body, rule):
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
    if not openai_client or not OPENAI_API_KEY:
        return None, 0.0

    label_list = ", ".join(AI_LABELS)
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
        norm = AI_LABEL_MAP.get(raw.lower())
        if not norm or norm == "None":
            return None, 0.0
        confidence = 0.75  # simple placeholder
        return norm, confidence
    except Exception as e:
        print("Error from OpenAI:", e)
        return None, 0.0


def record_labeled_email(
    gmail_id,
    thread_id,
    sender,
    subject,
    snippet,
    label,
    user_id,
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
            applied_label, is_ai_labeled, source, created_at, user_id
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(gmail_id) DO UPDATE SET
            thread_id = excluded.thread_id,
            sender = excluded.sender,
            subject = excluded.subject,
            snippet = excluded.snippet,
            applied_label = excluded.applied_label,
            is_ai_labeled = excluded.is_ai_labeled,
            source = excluded.source,
            user_id = excluded.user_id;
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
            user_id,
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
# Basic routes & auth
# -------------------------------------------------


@app.route("/")
def index():
    if "user_id" not in session:
        return redirect(url_for("login"))
    return redirect(url_for("rules_page"))


@app.route("/login")
def login():
    flow = Flow.from_client_secrets_file(
        WEB_CREDS_PATH,
        scopes=SCOPES,
        redirect_uri=GOOGLE_REDIRECT_URI,
    )
    authorization_url, state = flow.authorization_url(
        access_type="offline",
        include_granted_scopes="true",
        prompt="consent",  # forces refresh_token at least once
    )
    session["oauth_state"] = state
    return redirect(authorization_url)


@app.route("/oauth2callback")
def oauth2callback():
    state = session.get("oauth_state")
    if not state:
        return "Missing OAuth state in session", 400

    flow = Flow.from_client_secrets_file(
        WEB_CREDS_PATH,
        scopes=SCOPES,
        redirect_uri=GOOGLE_REDIRECT_URI,
        state=state,
    )
    flow.fetch_token(authorization_response=request.url)
    creds = flow.credentials

    # Get Google user info
    request_session = google_requests.Request()
    id_info = google_id_token.verify_oauth2_token(
        creds.id_token, request_session, GOOGLE_CLIENT_ID
    )

    google_user_id = id_info["sub"]
    email = id_info.get("email")

    conn = get_db_connection()
    cur = conn.cursor()
    now = datetime.utcnow().isoformat(timespec="seconds")

    cur.execute(
        """
        INSERT INTO users
        (google_user_id, email, access_token, refresh_token, token_expiry, created_at)
        VALUES (?, ?, ?, ?, ?, ?)
        ON CONFLICT(google_user_id) DO UPDATE SET
            email = excluded.email,
            access_token = excluded.access_token,
            refresh_token = excluded.refresh_token,
            token_expiry = excluded.token_expiry;
        """,
        (
            google_user_id,
            email,
            creds.token,
            creds.refresh_token,
            creds.expiry.isoformat() if creds.expiry else None,
            now,
        ),
    )

    cur.execute(
        "SELECT id FROM users WHERE google_user_id = ?;",
        (google_user_id,),
    )
    row = cur.fetchone()
    conn.commit()
    conn.close()

    user_id = row["id"]
    session["user_id"] = user_id
    session["email"] = email

    return redirect(url_for("rules_page"))


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.route("/health")
def health():
    return jsonify({"status": "ok"})


@app.route("/ai-status")
def ai_status():
    return jsonify(
        {"has_api_key": bool(OPENAI_API_KEY), "allowed_labels": AI_LABELS}
    )


# -------------------------------------------------
# Labeled emails count (per-user)
# -------------------------------------------------


@app.route("/api/labeled-emails-count", methods=["GET"])
def api_labeled_emails_count():
    user_id = get_current_user_id()
    if not user_id:
        return jsonify({"error": "Not logged in"}), 401

    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute(
        "SELECT COUNT(*) FROM labeled_emails WHERE user_id = ? OR user_id IS NULL;",
        (user_id,),
    )
    row = cur.fetchone()
    conn.close()
    count = row[0] if row else 0
    return jsonify({"count": count, "status": "Fetched labeled emails"})


# -------------------------------------------------
# Rules GUI & API
# -------------------------------------------------


@app.route("/rules", methods=["GET"])
def rules_page():
    if "user_id" not in session:
        return redirect(url_for("login"))
    return render_template("rules.html", user_email=session.get("email"))


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


def load_active_rules(user_id):
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute(
        """
        SELECT * FROM rules
        WHERE is_active = 1
          AND (user_id = ? OR user_id IS NULL)
        ORDER BY id;
        """,
        (user_id,),
    )
    rows = cur.fetchall()
    conn.close()
    return [db_row_to_rule(r) for r in rows]


@app.route("/api/rules", methods=["GET"])
def api_get_rules():
    user_id = get_current_user_id()
    if not user_id:
        return jsonify({"error": "Not logged in"}), 401

    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute(
        "SELECT * FROM rules WHERE user_id = ? OR user_id IS NULL ORDER BY id;",
        (user_id,),
    )
    rows = cur.fetchall()
    conn.close()
    rules = [db_row_to_rule(r) for r in rows]
    return jsonify(rules)


@app.route("/api/rules", methods=["POST"])
def api_create_rule():
    user_id = get_current_user_id()
    if not user_id:
        return jsonify({"error": "Not logged in"}), 401

    data = request.get_json() or {}
    label_name = (data.get("label_name") or "").strip()
    from_contains = (data.get("from_contains") or "").strip()
    subject_contains = (data.get("subject_contains") or "").strip()
    body_contains = (data.get("body_contains") or "").strip()
    is_active = 1 if data.get("is_active", True) else 0
    mark_as_read = 1 if data.get("mark_as_read", False) else 0

    if not label_name:
        return jsonify({"error": "label_name is required"}), 400

    now = datetime.utcnow().isoformat(timespec="seconds")

    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute(
        """
        INSERT INTO rules
        (user_id, label_name, from_contains, subject_contains, body_contains,
         is_active, mark_as_read, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?);
        """,
        (
            user_id,
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
    user_id = get_current_user_id()
    if not user_id:
        return jsonify({"error": "Not logged in"}), 401

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
    user_id = get_current_user_id()
    if not user_id:
        return jsonify({"error": "Not logged in"}), 401

    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("DELETE FROM rules WHERE id = ?;", (rule_id,))
    conn.commit()
    conn.close()
    return jsonify({"status": "deleted"})


# -------------------------------------------------
# Gmail labels – dropdown & unread counts
# -------------------------------------------------


@app.route("/api/gmail-labels", methods=["GET"])
def api_gmail_labels():
    user_id = get_current_user_id()
    if not user_id:
        return jsonify({"error": "Not logged in"}), 401

    try:
        service = get_gmail_service_for_user(user_id)
    except Exception as e:
        return jsonify({"error": f"Gmail auth failed: {e}"}), 500

    try:
        resp = service.users().labels().list(userId="me").execute()
        labels = resp.get("labels", [])
    except HttpError as e:
        return jsonify({"error": f"Gmail labels list failed: {e}"}), 500

    user_labels = [
        {"id": lbl["id"], "name": lbl.get("name", "")}
        for lbl in labels
        if lbl.get("type") == "user"
    ]
    return jsonify(user_labels)


@app.route("/api/labels", methods=["GET"])
def api_get_labels():
    user_id = get_current_user_id()
    if not user_id:
        return jsonify({"error": "Not logged in"}), 401

    try:
        service = get_gmail_service_for_user(user_id)
    except Exception as e:
        return jsonify({"error": f"Gmail auth failed: {e}"}), 500

    try:
        resp = service.users().labels().list(userId="me").execute()
        labels = resp.get("labels", [])
    except HttpError as e:
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
        except HttpError as e:
            print(f"Error fetching label detail for {lbl.get('name')}: {e}")
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
    user_id = get_current_user_id()
    if not user_id:
        return jsonify({"error": "Not logged in"}), 401

    try:
        service = get_gmail_service_for_user(user_id)
    except Exception as e:
        return jsonify({"error": f"Gmail auth failed: {e}"}), 500

    user = "me"
    all_ids = []
    page_token = None

    try:
        while True:
            resp = (
                service.users()
                .messages()
                .list(
                    userId=user,
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
    except HttpError as e:
        return jsonify({"error": f"Gmail list failed: {e}"}), 500

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
                userId=user,
                body={"ids": chunk, "removeLabelIds": ["UNREAD"]},
            ).execute()
    except HttpError as e:
        return jsonify({"error": f"Gmail batchModify failed: {e}"}), 500

    return jsonify(
        {
            "status": "ok",
            "updated": len(all_ids),
            "message": f"Marked {len(all_ids)} messages as read.",
        }
    )


# -------------------------------------------------
# Run labeler – rules + AI (per-user)
# -------------------------------------------------


@app.route("/run-labeler", methods=["POST"])
def run_labeler():
    user_id = get_current_user_id()
    if not user_id:
        return jsonify({"error": "Not logged in"}), 401

    try:
        service = get_gmail_service_for_user(user_id)
    except Exception as e:
        return jsonify({"error": f"Gmail auth failed: {e}"}), 500

    rules = load_active_rules(user_id)
    rule_count = 0
    ai_count = 0
    total = 0

    try:
        msg_list = (
            service.users()
            .messages()
            .list(userId="me", labelIds=["INBOX"], maxResults=50)
            .execute()
        )
        messages = msg_list.get("messages", [])
    except HttpError as e:
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
        except HttpError as e:
            print("Error fetching full message:", e)
            continue

        sender, subject, snippet, body = extract_email_fields(full)
        thread_id = full.get("threadId", "")

        matched_label = None
        matched_rule_mark_read = False

        # 1) Try rules
        for rule in rules:
            if email_matches_rule(sender, subject, body, rule):
                matched_label = rule["label_name"]
                matched_rule_mark_read = rule.get("mark_as_read", False)
                apply_label_to_message(
                    service,
                    gmail_id,
                    matched_label,
                    remove_from_inbox=True,
                    mark_as_read=matched_rule_mark_read,
                )
                record_labeled_email(
                    gmail_id,
                    thread_id,
                    sender,
                    subject,
                    snippet,
                    matched_label,
                    user_id=user_id,
                    is_ai_labeled=False,
                    source="rule",
                )
                rule_count += 1
                break

        # 2) AI label if no rule matched
        if not matched_label:
            label, conf = ai_suggest_label(sender, subject, body)
            if label:
                apply_label_to_message(
                    service,
                    gmail_id,
                    label,
                    remove_from_inbox=True,
                    mark_as_read=False,
                )
                record_labeled_email(
                    gmail_id,
                    thread_id,
                    sender,
                    subject,
                    snippet,
                    label,
                    user_id=user_id,
                    is_ai_labeled=True,
                    source="ai",
                )
                record_ai_suggestion(gmail_id, label, conf)
                ai_count += 1

    return jsonify(
        {
            "status": "ok",
            "processed": total,
            "rule_labeled": rule_count,
            "ai_labeled": ai_count,
        }
    )


# -------------------------------------------------
# Learn from user labels (per-user)
# -------------------------------------------------


@app.route("/learn-from-user-labels", methods=["POST"])
def learn_from_user_labels():
    user_id = get_current_user_id()
    if not user_id:
        return jsonify({"error": "Not logged in"}), 401

    try:
        service = get_gmail_service_for_user(user_id)
    except Exception as e:
        return jsonify({"error": f"Gmail auth failed: {e}"}), 500

    conn = get_db_connection()
    cur = conn.cursor()

    # Existing gmail_ids for this user (or legacy null user_id)
    cur.execute(
        "SELECT gmail_id FROM labeled_emails WHERE user_id = ? OR user_id IS NULL;",
        (user_id,),
    )
    existing_ids = {row["gmail_id"] for row in cur.fetchall()}

    user = "me"
    label_list_resp = service.users().labels().list(userId=user).execute()
    labels = label_list_resp.get("labels", [])

    user_label_ids = [lbl["id"] for lbl in labels if lbl.get("type") == "user"]

    user_labeled_added = 0

    # 1) Pull user-labeled emails from Gmail into labeled_emails
    for lid in user_label_ids:
        try:
            msg_list = (
                service.users()
                .messages()
                .list(userId=user, labelIds=[lid], maxResults=50)
                .execute()
            )
        except HttpError as e:
            print("Error listing messages for label", lid, e)
            continue

        for m in msg_list.get("messages", []):
            gmail_id = m["id"]
            if gmail_id in existing_ids:
                continue

            try:
                full = (
                    service.users()
                    .messages()
                    .get(userId=user, id=gmail_id, format="full")
                    .execute()
                )
            except HttpError as e:
                print("Error fetching full message:", e)
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
                user_id=user_id,
                is_ai_labeled=False,
                source="user",
            )
            existing_ids.add(gmail_id)
            user_labeled_added += 1

    # 2) From those labeled emails, learn (label, domain) patterns
    cur.execute(
        """
        SELECT sender, applied_label
        FROM labeled_emails
        WHERE source = 'user' AND (user_id = ? OR user_id IS NULL);
        """,
        (user_id,),
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
            WHERE (user_id = ? OR user_id IS NULL)
              AND label_name = ?
              AND from_contains = ?
              AND is_active = 1
            LIMIT 1;
            """,
            (user_id, label, f"@{domain}"),
        )
        exists = cur.fetchone()
        if exists:
            continue

        now = datetime.utcnow().isoformat(timespec="seconds")
        cur.execute(
            """
            INSERT INTO rules
            (user_id, label_name, from_contains, subject_contains, body_contains,
             is_active, mark_as_read, created_at, updated_at)
            VALUES (?, ?, ?, '', '', 1, 0, ?, ?);
            """,
            (user_id, label, f"@{domain}", now, now),
        )
        rules_created += 1

    conn.commit()
    conn.close()

    return jsonify(
        {
            "status": "ok",
            "user_labeled_added": user_labeled_added,
            "rules_created": rules_created,
        }
    )


# -------------------------------------------------
# Main
# -------------------------------------------------

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
