from flask import Flask
from config import config_by_name

def create_app(config_name="default"):
    app = Flask(
        __name__,
        template_folder="templates",
        static_folder="static",
        static_url_path="/static"
    )
    app.config.from_object(config_by_name.get(config_name, config_by_name["default"]))

    from app.routes.analyze import analyze_bp
    from app.routes.reports import reports_bp
    from app.routes.auth import auth_bp
    app.register_blueprint(analyze_bp)
    app.register_blueprint(reports_bp)
    app.register_blueprint(auth_bp)

    return app
