import os
import logging

from flask import Flask
from dotenv import load_dotenv

from db import init_db

from routes_misc import misc_bp
from routes_rules import rules_bp
from routes_relabel import relabel_bp

# -------------------------------------------------
# App factory
# -------------------------------------------------


def create_app():
    # Load .env once here
    load_dotenv()

    # Logging
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s - %(message)s",
    )
    logger = logging.getLogger(__name__)

    app = Flask(__name__)
    app.secret_key = os.environ.get("FLASK_SECRET_KEY", "dev-secret-change-me")

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
    app.run(host="0.0.0.0", port=5000, debug=True)
