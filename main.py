import sys

# allow imports from /backend
sys.path.append("backend")

from app import app  # backend/app.py must define: app = Flask(__name__)

# optional local run (Railway uses gunicorn, not this)
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)
