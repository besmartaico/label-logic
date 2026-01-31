import os
import json
import logging
from datetime import datetime

from flask import Blueprint, jsonify, redirect, request, url_for, session

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


def _load_google_client_config() -> dict:
    """
    Loads OAuth client config from env var GOOGLE_CREDENTIALS_JSON.

    Expected content: the downloaded OAuth client JSON from Google Cloud Console.
    Can be either {"web": {...}} or {"installed": {...}}. ("web" is recommended for hosted apps.)
    """
    raw = os.environ.get("GOOGLE_CREDENTIALS_JSON", "").strip()
    if not raw:
        raise RuntimeError(
            "Missing GOOGLE_CREDENTIALS_JSON env var. "
            "Set it in your hosting provider environment variables to your OAuth client JSON."
        )

    try:
        return json.loads(raw)
    except Exception as e:
        raise RuntimeError(f"GOOGLE_CREDENTIALS_JSON is not valid JSON: {e}") from e


def _get_redirect_uri() -> str:
    """
    Returns the OAuth redirect URI.

    Priority:
    1) If GOOGLE_OAUTH_REDIRECT_URI is set, use it (explicit override).
    2) Otherwise build from the current request host (works locally + Railway/Render).
    """
    forced = os.environ.get("GOOGLE_OAUTH_REDIRECT_URI", "").strip()
    if forced:
        return forced

    # Build from the request host so we never accidentally redirect to localhost in production.
    # Example on Railway: https://your-app.up.railway.app/oauth2callback
    return request.url_root.rstrip("/") + url_for("misc.oauth2callback")


def _build_flow(state: str | None = None) -> Flow:
    """
    Builds a Google OAuth Flow using env-based client config and a redirect URI
    that matches the current host.
    """
    client_config = _load_google_client_config()

    kwargs = dict(
        client_config=client_config,
        scopes=ALL_SCOPES,
        redirect_uri=_get_redirect_uri(),
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

    # After ProxyFix (in app.py), request.url should reflect the correct scheme/host.
    # NOTE: oauthlib may raise a Warning as an exception when the returned token scopes
    # do not match the requested scopes ("Scope has changed ..."). We handle that here
    # and return a clear, actionable response instead of a 500.
    try:
        flow.fetch_token(authorization_response=request.url)
    except Exception as e:
        msg = str(e)
        logger.exception("OAuth token fetch failed")

        # Common case: Google did not grant the Gmail scope we requested.
        if "Scope has changed" in msg or "scope" in msg.lower():
            # Clear state so a retry starts fresh.
            session.pop("state", None)

            return (
                jsonify(
                    {
                        "error": "Google did not grant the requested Gmail permissions.",
                        "details": msg,
                        "requested_scopes": ALL_SCOPES,
                        "next_steps": [
                            "1) In Google Cloud Console, ensure Gmail API is enabled for this project.",
                            "2) Ensure your OAuth consent screen is configured; if in Testing, add your Google account as a Test User.",
                            "3) Confirm the deployed GOOGLE_CREDENTIALS_JSON is the OAuth Client for the same project.",
                            "4) Delete any previously stored credentials for this user (google_accounts table) and re-auth at /auth/google.",
                        ],
                    }
                ),
                400,
            )

        return jsonify({"error": msg}), 400

    creds = flow.credentials

    # Double-check that the token actually includes gmail.modify.
    # (Some auth flows can complete with reduced scopes.)
    granted_scopes = set(getattr(creds, "scopes", []) or [])
    if "https://www.googleapis.com/auth/gmail.modify" not in granted_scopes:
        session.pop("state", None)
        return (
            jsonify(
                {
                    "error": "OAuth completed but Gmail modify permission was not granted.",
                    "granted_scopes": sorted(granted_scopes),
                    "requested_scopes": ALL_SCOPES,
                    "next_steps": [
                        "Re-run /auth/google and ensure you approve Gmail access on the consent screen.",
                        "If you do not see a Gmail permission prompt, delete stored credentials for this user and try again.",
                        "If still missing, verify Gmail API is enabled and your account is allowed (Test Users / publishing status).",
                    ],
                }
            ),
            400,
        )

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

    # ✅ FIX: Properly indented try/except and return a clear error if save fails
    try:
        save_credentials(google_user_id, email, creds)
        logger.info("Saved credentials for %s (%s)", email, google_user_id)
    except Exception as e:
        logger.exception("save_credentials failed for %s (%s)", email, google_user_id)
        return jsonify({"error": f"save_credentials failed: {e}"}), 500

    session["google_user_id"] = google_user_id
    session["email"] = email

    logger.info("User logged in: %s (%s)", email, google_user_id)
    return redirect(url_for("rules.rules_page"))


@misc_bp.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("misc.auth_google"))


# -------------------------------------------------------------------
# Debug routes (temporary; remove once resolved)
# -------------------------------------------------------------------

@misc_bp.route("/debug/session", methods=["GET"])
def debug_session():
    """
    Confirms whether the browser session contains the expected values after OAuth.
    """
    return jsonify(
        {
            "google_user_id": session.get("google_user_id"),
            "email": session.get("email"),
            "has_state": bool(session.get("state")),
            "cookies_present": bool(request.headers.get("Cookie")),
            "host": request.host,
            "url_root": request.url_root,
            "scheme": request.scheme,
        }
    )


@misc_bp.route("/debug/creds", methods=["GET"])
def debug_creds():
    """
    Confirms whether we can find stored credentials for the current session user in the DB.
    NOTE: Credentials are stored in google_accounts (see db.save_credentials / db.load_credentials).
    """
    uid = session.get("google_user_id")
    if not uid:
        return jsonify({"error": "no session google_user_id"}), 401

    try:
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute(
            """
            SELECT email, credentials_json
            FROM google_accounts
            WHERE google_user_id = %s;
            """,
            (uid,),
        )
        row = cur.fetchone()
        conn.close()

        return jsonify(
            {
                "google_user_id": uid,
                "found_in_db": bool(row),
                "db_email": row["email"] if row else None,
                "has_credentials_json": bool(row["credentials_json"]) if row else False,
            }
        )
    except Exception as e:
        logger.exception("debug_creds failed")
        return jsonify({"error": str(e)}), 500


@misc_bp.route("/debug/db-path", methods=["GET"])
def debug_db_path():
    """
    Postgres-friendly DB debug endpoint (replaces sqlite PRAGMA usage).
    """
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute(
            """
            SELECT
              current_database() AS db,
              inet_server_addr() AS server_addr,
              inet_server_port() AS server_port;
            """
        )
        info = cur.fetchone()
        conn.close()

        return jsonify(
            {
                "cwd": os.getcwd(),
                "database": info,
                "has_database_url": bool(os.environ.get("DATABASE_URL")),
                "pgsslmode": os.environ.get("PGSSLMODE", "require"),
            }
        )
    except Exception as e:
        logger.exception("debug_db_path failed")
        return jsonify({"error": str(e)}), 500


@misc_bp.route("/api/labeled-emails-count", methods=["GET"])
def labeled_emails_count():
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("SELECT COUNT(*) AS count FROM labeled_emails;")
    row = cur.fetchone()
    conn.close()
    count = row["count"] if row else 0
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
            WHERE label_name = %s
              AND from_contains = %s
              AND is_active = TRUE
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
            VALUES (%s, %s, '', '', TRUE, FALSE, %s, %s);
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
