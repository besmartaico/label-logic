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
    if not os.environ.get("RENDER") and not os.environ.get("RENDER_EXTERNAL_URL"):
        load_dotenv()

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s - %(message)s",
    )
    logger = logging.getLogger(__name__)

    app = Flask(__name__)
    app.secret_key = os.environ.get("FLASK_SECRET_KEY", "dev-secret-change-me")
    app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_host=1)
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

    # Start server-side scheduler (runs in background thread, survives browser close)
    # Guard against double-start in development reloader
    if not app.debug or os.environ.get("WERKZEUG_RUN_MAIN") == "true":
        try:
            from scheduler import init_scheduler
            init_scheduler()
            logger.info("Server-side scheduler started.")
        except Exception:
            logger.exception("Failed to start server-side scheduler — scheduled jobs will not run.")

    return app


app = create_app()

if __name__ == "__main__":
    port = int(os.environ.get("PORT", "5000"))
    app.run(host="0.0.0.0", port=port, debug=True)
