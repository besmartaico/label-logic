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

    return request.url_root.rstrip("/") + url_for("misc.oauth2callback")


def _build_flow(state: str | None = None) -> Flow:
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
    # ✅ send authenticated users to the dashboard endpoint
    return redirect(url_for("rules.dashboard_page"))


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

    try:
        flow.fetch_token(authorization_response=request.url)
    except Exception as e:
        msg = str(e)
        logger.exception("OAuth token fetch failed")

        if "Scope has changed" in msg or "scope" in msg.lower():
            session.pop("state", None)
            return (
                jsonify(
                    {
                        "error": "Google did not grant the requested Gmail permissions.",
                        "details": msg,
                        "requested_scopes": ALL_SCOPES,
                        "next_steps": [
                            "1) Ensure Gmail API is enabled for this project.",
                            "2) Ensure OAuth consent screen is configured; if in Testing, add your account as a Test User.",
                            "3) Confirm GOOGLE_CREDENTIALS_JSON is for the same project.",
                            "4) Delete stored credentials for this user and re-auth at /auth/google.",
                        ],
                    }
                ),
                400,
            )

        return jsonify({"error": msg}), 400

    creds = flow.credentials

    granted_scopes = set(getattr(creds, "scopes", []) or [])
    if "https://www.googleapis.com/auth/gmail.modify" not in granted_scopes:
        session.pop("state", None)
        return (
            jsonify(
                {
                    "error": "OAuth completed but Gmail modify permission was not granted.",
                    "granted_scopes": sorted(granted_scopes),
                    "requested_scopes": ALL_SCOPES,
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

    try:
        save_credentials(google_user_id, email, creds)
        logger.info("Saved credentials for %s (%s)", email, google_user_id)
    except Exception as e:
        logger.exception("save_credentials failed for %s (%s)", email, google_user_id)
        return jsonify({"error": f"save_credentials failed: {e}"}), 500

    session["google_user_id"] = google_user_id
    session["email"] = email

    logger.info("User logged in: %s (%s)", email, google_user_id)
    # ✅ send users to dashboard after login
    return redirect(url_for("rules.dashboard_page"))


@misc_bp.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("misc.auth_google"))


# -------------------------------------------------------------------
# Debug routes (temporary; remove once resolved)
# -------------------------------------------------------------------

@misc_bp.route("/debug/session", methods=["GET"])
def debug_session():
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
    uid = session.get("google_user_id")
    if not uid:
        return jsonify({"error": "No google_user_id in session"}), 401

    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("SELECT google_user_id, email, updated_at FROM google_accounts WHERE google_user_id = %s", (uid,))
    row = cur.fetchone()
    conn.close()

    return jsonify({"found": bool(row), "row": dict(row) if row else None})


@misc_bp.route("/debug/gmail-profile", methods=["GET"])
def debug_gmail_profile():
    try:
        service = get_gmail_service_for_current_user()
        profile = service.users().getProfile(userId="me").execute()
        return jsonify({"ok": True, "profile": profile})
    except Exception as e:
        logger.exception("debug_gmail_profile failed")
        return jsonify({"ok": False, "error": str(e)}), 500


@misc_bp.route("/debug/list-messages", methods=["GET"])
def debug_list_messages():
    try:
        n = int(request.args.get("n", "5"))
    except Exception:
        n = 5

    try:
        service = get_gmail_service_for_current_user()
        resp = service.users().messages().list(userId="me", maxResults=n).execute()
        return jsonify({"ok": True, "response": resp})
    except Exception as e:
        logger.exception("debug_list_messages failed")
        return jsonify({"ok": False, "error": str(e)}), 500


@misc_bp.route("/debug/list-labels", methods=["GET"])
def debug_list_labels():
    try:
        service = get_gmail_service_for_current_user()
        resp = service.users().labels().list(userId="me").execute()
        return jsonify({"ok": True, "response": resp})
    except Exception as e:
        logger.exception("debug_list_labels failed")
        return jsonify({"ok": False, "error": str(e)}), 500


@misc_bp.route("/debug/extract-domain", methods=["GET"])
def debug_extract_domain():
    sender = request.args.get("sender", "")
    return jsonify(
        {
            "sender": sender,
            "domain": extract_domain_from_sender(sender),
        }
    )


@misc_bp.route("/debug/now", methods=["GET"])
def debug_now():
    return jsonify({"utc_now": datetime.utcnow().isoformat(timespec="seconds") + "Z"})
