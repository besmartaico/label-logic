import os
import json
import logging
from datetime import datetime

from flask import Blueprint, jsonify, redirect, request, url_for, session

from dotenv import load_dotenv

from google_auth_oauthlib.flow import Flow
from google.oauth2 import id_token
from google.auth.transport import requests as google_requests

from db import (
    get_db_connection,
    save_credentials,
    extract_domain_from_sender,
)
from gmail_client import get_gmail_service_for_current_user
from ai_labels import get_allowed_ai_labels

logger = logging.getLogger(__name__)

misc_bp = Blueprint("misc", __name__)

# Scopes for OAuth
GMAIL_SCOPES = ["https://www.googleapis.com/auth/gmail.modify"]
OIDC_SCOPES = ["openid", "https://www.googleapis.com/auth/userinfo.email"]
ALL_SCOPES = GMAIL_SCOPES + OIDC_SCOPES

GOOGLE_OAUTH_REDIRECT_URI = os.environ.get(
    "GOOGLE_OAUTH_REDIRECT_URI", "http://localhost:5000/oauth2callback"
)


def _load_google_client_config() -> dict:
    """
    Loads OAuth client config from env var GOOGLE_CREDENTIALS_JSON.

    Expected content: the downloaded OAuth client JSON from Google Cloud Console.
    Can be either {"web": {...}} or {"installed": {...}}. (Web is recommended for hosted apps.)
    """
    raw = os.environ.get("GOOGLE_CREDENTIALS_JSON", "").strip()
    if not raw:
        raise RuntimeError(
            "Missing GOOGLE_CREDENTIALS_JSON env var. "
            "Set it in Railway Variables to your OAuth client JSON."
        )

    try:
        return json.loads(raw)
    except Exception as e:
        raise RuntimeError(
            f"GOOGLE_CREDENTIALS_JSON is not valid JSON: {e}"
        ) from e


def _build_flow(state: str | None = None) -> Flow:
    """
    Builds a Google OAuth Flow using env-based client config and the configured redirect URI.
    """
    client_config = _load_google_client_config()

    # Flow.from_client_config expects the full JSON dict (e.g., {"web": {...}}).
    kwargs = dict(
        client_config=client_config,
        scopes=ALL_SCOPES,
        redirect_uri=GOOGLE_OAUTH_REDIRECT_URI,
    )
    if state:
        kwargs["state"] = state

    return Flow.from_client_config(**kwargs)


@misc_bp.route("/")
def index():
    if "google_user_id" not in session:
        return redirect(url_for("misc.auth_google"))
    return redirect(url_for("rules.rules_page"))


@misc_bp.route("/health")
def health():
    return jsonify({"status": "ok"})


@misc_bp.route("/ai-status")
def ai_status():
    has_key = bool(os.environ.get("OPENAI_API_KEY", ""))
    return jsonify(
        {
            "has_api_key": has_key,
            "allowed_labels": get_allowed_ai_labels(),
        }
    )


@misc_bp.route("/auth/google")
def auth_google():
    try:
        flow = _build_flow()
    except Exception as e:
        logger.exception("Failed to build OAuth flow in /auth/google")
        return jsonify({"error": str(e)}), 500

    auth_url, state = flow.authorization_url(
        access_type="offline",
        include_granted_scopes="true",
        prompt="consent",
    )
    session["state"] = state
    return redirect(auth_url)


@misc_bp.route("/oauth2callback")
def oauth2callback():
    state = session.get("state")
    if not state:
        return jsonify({"error": "Missing OAuth state"}), 400

    try:
        flow = _build_flow(state=state)
    except Exception as e:
        logger.exception("Failed to build OAuth flow in /oauth2callback")
        return jsonify({"error": str(e)}), 500

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
    return redirect(url_for("rules.rules_page"))


@misc_bp.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("misc.auth_google"))


@misc_bp.route("/api/labeled-emails-count", methods=["GET"])
def labeled_emails_count():
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("SELECT COUNT(*) FROM labeled_emails;")
    row = cur.fetchone()
    conn.close()
    count = row[0] if row else 0
    return jsonify({"count": count, "status": "Fetched labeled emails"})


@misc_bp.route("/learn-from-user-labels", methods=["POST"])
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

    from gmail_client import extract_email_fields
    from db import record_labeled_email

    for lid in user_label_ids:
        try:
            msg_list = (
                service.users()
                .messages()
                .list(userId=user_id, labelIds=[lid], maxResults=50)
                .execute()
            )
        except Exception:
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
            except Exception:
                logger.exception("Error fetching full message in learn_from_user_labels")
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

    # Domain → rule creation
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
