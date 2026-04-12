import os
from flask import Flask
from flask_wtf import CSRFProtect
from app.extensions import limiter
from app.config import SECRET_KEY

csrf = CSRFProtect()

def create_app():
    # Base directory (app folder)
    BASE_DIR = os.path.abspath(os.path.dirname(__file__))

    # Project root (one level up)
    PROJECT_ROOT = os.path.abspath(os.path.join(BASE_DIR, ".."))

    # Correct paths (your case: templates outside app)

    # Create Flask app
    app = Flask(
        __name__,
        template_folder=os.path.join(PROJECT_ROOT, "templates"),
        static_folder=os.path.join(PROJECT_ROOT, "static")
    )

    # Config
    app.config["SECRET_KEY"] = SECRET_KEY
    app.config["DEBUG"] = os.environ.get("DEBUG", "False").lower() == "true"
    app.config["SESSION_COOKIE_HTTPONLY"] = True
    app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
    app.config["SESSION_COOKIE_SECURE"] = not app.config["DEBUG"]

    # Rate limiter storage: use Redis if available, fallback to memory
    redis_url = os.environ.get("REDIS_URL")
    if redis_url:
        app.config["RATELIMIT_STORAGE_URI"] = redis_url
        print(f"INFO: Rate limiter using Redis: {redis_url.split('@')[-1] if '@' in redis_url else redis_url}")
    else:
        app.config["RATELIMIT_STORAGE_URI"] = "memory://"
        print("WARNING: Rate limiter using in-memory storage. Set REDIS_URL for production.")

    csrf.init_app(app)
    limiter.init_app(app)

    # Import and register blueprints
    from app.routes.auth import auth_bp
    from app.routes.general import general_bp
    from app.routes.items import items_bp
    from app.routes.admin import admin_bp
    from app.routes.staff import staff_bp
    from app.routes.student import student_bp

    app.register_blueprint(auth_bp)
    app.register_blueprint(general_bp)
    app.register_blueprint(items_bp)
    app.register_blueprint(admin_bp)
    app.register_blueprint(staff_bp)
    app.register_blueprint(student_bp)

    return app