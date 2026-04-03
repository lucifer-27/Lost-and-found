import os
from datetime import timedelta
from flask import Flask, session
from .config import SECRET_KEY, project_root


def create_app():
    app = Flask(
        __name__,
        template_folder=os.path.join(project_root, "templates"),
        static_folder=os.path.join(project_root, "static"),
    )
    app.secret_key = SECRET_KEY
    app.config["TEMPLATES_AUTO_RELOAD"] = True
    app.permanent_session_lifetime = timedelta(days=30)
    app.config["SESSION_COOKIE_HTTPONLY"] = True
    app.config["SESSION_COOKIE_SAMESITE"] = "Lax"

    @app.before_request
    def keep_logged_in_users_signed_in():
        if "user" in session:
            session.permanent = True

    # Register blueprints
    from .routes.auth import auth_bp
    from .routes.student import student_bp
    from .routes.staff import staff_bp
    from .routes.admin import admin_bp
    from .routes.items import items_bp
    from .routes.general import general_bp

    app.register_blueprint(auth_bp)
    app.register_blueprint(student_bp)
    app.register_blueprint(staff_bp)
    app.register_blueprint(admin_bp)
    app.register_blueprint(items_bp)
    app.register_blueprint(general_bp)

    return app
