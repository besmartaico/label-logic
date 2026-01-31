import os
import logging

from flask import Flask
from dotenv import load_dotenv
from werkzeug.middleware.proxy_fix import ProxyFix

from db import init_db

from routes_misc import misc_bp
from routes_rules import rules_bp
from routes_relabel import relabel_bp

# -------------------------------------------------
# App factory
# -------------------------------------------------


def create_app():
    # Only load .env for local development.
    # On Render, environment variables are configured in the dashboard and we do NOT
    # want a committed .env to override them (especially redirect URIs).
    if not os.environ.get("RENDER") and not os.environ.get("RENDER_EXTERNAL_URL"):
        load_dotenv()

    # Logging
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s - %(message)s",
    )
    logger = logging.getLogger(__name__)

    app = Flask(__name__)
    app.secret_key = os.environ.get("FLASK_SECRET_KEY", "dev-secret-change-me")

    # Trust reverse-proxy headers (Render) so Flask generates correct external URLs
    # and sees the correct scheme (https) and host (your onrender.com domain).
    app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_host=1)

    # Cookie/security defaults (helps when running behind https)
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

    return app


app = create_app()

if __name__ == "__main__":
    # Local dev convenience:
    # Render/Gunicorn will ignore this and bind using its own PORT.
    port = int(os.environ.get("PORT", "5000"))
    app.run(host="0.0.0.0", port=port, debug=True)
