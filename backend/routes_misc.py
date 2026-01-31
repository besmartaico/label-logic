import os
import json
import logging
from datetime import datetime

from flask import Blueprint, jsonify, redirect, request, url_for, session, current_app

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
    raw = os.environ.get("GOOGLE_CREDENTIALS_JSON", "").strip()
    if not raw:
        raise RuntimeError(
            "Missing GOOGLE_CREDENTIALS_JSON env var. "
            "Set it in Railway variables to your OAuth client JSON."
        )
    try:
        return json.loads(raw)
    except Exception as e:
        raise RuntimeError(f"GOOGLE_CREDENTIALS_JSON is not valid JSON: {e}") from e


def _get_redirect_uri() -> str:
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


def _safe_redirect_to_app_home():
    """
    Avoids BuildError if endpoints changed.
    Priority:
      1) rules.dashboard_page (new dashboard)
      2) rules.rules_page (older default)
      3) misc.health (always exists)
    """
    vf = current_app.view_functions or {}
    if "rules.dashboard_page" in vf:
        return redirect(url_for("rules.dashboard_page"))
    if "rules.rules_page" in vf:
        return redirect(url_for("rules.rules_page"))
    return redirect(url_for("misc.health"))


@misc_bp.route("/")
def index():
    if "google_user_id" not in session:
        return redirect(url_for("misc.auth_google"))
    return _safe_redirect_to_app_home()


@misc_bp.route("/health")
def health():
    return jsonify({"status": "ok", "utc": datetime.utcnow().isoformat(timespec="seconds") + "Z"})


@misc_bp.route("/debug/routes")
def debug_routes():
    vf = current_app.view_functions or {}
    # Return sorted endpoint names so you can see what's actually registered in prod
    return jsonify({"endpoints": sorted(vf.keys())})


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
                    }
                ),
                400,
            )
        return jsonify({"error": msg}), 400

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

    try:
        save_credentials(google_user_id, email, creds)
    except Exception as e:
        logger.exception("save_credentials failed")
        return jsonify({"error": f"save_credentials failed: {e}"}), 500

    session["google_user_id"] = google_user_id
    session["email"] = email

    return _safe_redirect_to_app_home()


@misc_bp.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("misc.auth_google"))
