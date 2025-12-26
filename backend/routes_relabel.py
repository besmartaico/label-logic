import logging
from flask import Blueprint, render_template, jsonify, request

from gmail_client import (
    get_gmail_service_for_current_user,
    get_label_id_by_name,
    get_or_create_gmail_label,
)
from googleapiclient.errors import HttpError

logger = logging.getLogger(__name__)

relabel_bp = Blueprint("relabel", __name__)


@relabel_bp.route("/relabel", methods=["GET"])
def relabel_page():
    from flask import session, redirect, url_for

    if "google_user_id" not in session:
        return redirect(url_for("misc.auth_google"))
    return render_template("relabel.html")


@relabel_bp.route("/api/relabel", methods=["POST"])
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
