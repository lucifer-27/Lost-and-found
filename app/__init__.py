import os
from flask import Flask
from flask_wtf import CSRFProtect
from app.extensions import limiter

csrf = CSRFProtect()

def create_app():
    # Base directory (app folder)
    BASE_DIR = os.path.abspath(os.path.dirname(__file__))

    # Project root (one level up)
    PROJECT_ROOT = os.path.abspath(os.path.join(BASE_DIR, ".."))

    # Correct paths (your case: templates outside app)
    TEMPLATE_DIR = os.path.join(PROJECT_ROOT, "templates")
    STATIC_DIR = os.path.join(PROJECT_ROOT, "static")



    # Create Flask app
    app = Flask(
        __name__,
        template_folder=TEMPLATE_DIR,
        static_folder=STATIC_DIR
    )



    # Config
    app.config["SECRET_KEY"] = "test_secret"
    app.config["SESSION_COOKIE_HTTPONLY"] = True
    app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
    app.config["SESSION_COOKIE_SECURE"] = False
    app.config["RATELIMIT_STORAGE_URI"] = "memory://"

    csrf.init_app(app)
    limiter.init_app(app)
    
    from app.extensions import init_db
    init_db()

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