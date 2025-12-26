import os
import base64
import logging

from google.oauth2.credentials import Credentials
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError
from google.auth.transport.requests import Request as GoogleAuthRequest

from flask import session

from db import load_credentials, save_credentials

logger = logging.getLogger(__name__)

# Only Gmail scope here; OIDC scopes live with the auth routes.
GMAIL_SCOPES = ["https://www.googleapis.com/auth/gmail.modify"]


def is_probably_valid_label_name(name: str) -> bool:
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
    google_user_id = session.get("google_user_id")
    if not google_user_id:
        raise RuntimeError("Not logged in with Google")

    creds_json = load_credentials(google_user_id)
    if not creds_json:
        raise RuntimeError("No stored credentials for this user")

    import json

    data = json.loads(creds_json)
    creds = Credentials.from_authorized_user_info(data, GMAIL_SCOPES)

    if not creds.valid:
        if creds.expired and creds.refresh_token:
            logger.info("Refreshing Gmail credentials for user %s", google_user_id)
            creds.refresh(GoogleAuthRequest())
            email = session.get("email", "")
            save_credentials(google_user_id, email, creds)
        else:
            raise RuntimeError("Credentials invalid and no refresh token")

    return build("gmail", "v1", credentials=creds)


def get_or_create_gmail_label(service, label_name):
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
    from googleapiclient.errors import HttpError

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

    try:
        service.users().messages().modify(
            userId="me", id=gmail_id, body=body
        ).execute()
    except HttpError:
        logger.exception("Failed to modify message %s", gmail_id)


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
