import os
import logging
import traceback

from flask import Flask, jsonify, request
from dotenv import load_dotenv
from werkzeug.middleware.proxy_fix import ProxyFix
from werkzeug.exceptions import HTTPException
from jinja2 import TemplateNotFound

from db import init_db

from routes_misc import misc_bp
from routes_rules import rules_bp
from routes_relabel import relabel_bp


def create_app():
    # Load .env locally only (Railway uses env vars)
    if not os.environ.get("RAILWAY_ENVIRONMENT") and not os.environ.get("RENDER") and not os.environ.get("RENDER_EXTERNAL_URL"):
        load_dotenv()

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s - %(message)s",
    )
    logger = logging.getLogger(__name__)

    app = Flask(__name__)
    app.secret_key = os.environ.get("FLASK_SECRET_KEY", "dev-secret-change-me")

    # Trust reverse proxy headers (Railway/Render) for correct scheme/host
    app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_host=1)

    # Cookie/security defaults (safe for Railway https)
    app.config["PREFERRED_URL_SCHEME"] = "https"
    app.config["SESSION_COOKIE_SECURE"] = True
    app.config["SESSION_COOKIE_SAMESITE"] = "Lax"

    # Init DB
    init_db()
    logger.info("Database initialized.")

    # Register blueprints
    app.register_blueprint(misc_bp)
    app.register_blueprint(rules_bp)
    app.register_blueprint(relabel_bp)

    # -------------------------------------------------
    # Global error handler so Railway logs ALWAYS show the real cause
    # -------------------------------------------------
    @app.errorhandler(TemplateNotFound)
    def handle_template_not_found(e):
        logger.exception("TemplateNotFound: %s", e)
        return (
            f"Template not found: {e}. Check backend/templates and which route is rendering it.",
            500,
        )

    @app.errorhandler(Exception)
    def handle_unexpected_exception(e):
        # Let Flask/Werkzeug handle expected HTTP errors (404, 401, etc.)
        if isinstance(e, HTTPException):
            return e

        logger.exception("Unhandled exception on %s %s", request.method, request.path)

        # Return JSON for API calls or when browser requests JSON
        wants_json = (
            request.path.startswith("/api/")
            or request.path.startswith("/debug/")
            or "application/json" in (request.headers.get("Accept") or "")
        )
        if wants_json:
            return (
                jsonify(
                    {
                        "error": "Internal Server Error",
                        "path": request.path,
                        "method": request.method,
                        "message": str(e),
                        "trace": traceback.format_exc(),
                    }
                ),
                500,
            )

        # Otherwise return a simple text response (the full stack is still in Railway logs)
        return "Internal Server Error. Check Railway logs for traceback.", 500

    return app


app = create_app()

if __name__ == "__main__":
    port = int(os.environ.get("PORT", "5000"))
    app.run(host="0.0.0.0", port=port, debug=True)
