import os
from flask import Flask, redirect, url_for
from config import Config
from database.database import init_db
from routes.auth_routes import auth_bp
from routes.user_routes import user_bp
from routes.admin_routes import admin_bp
from timeutil import to_local

def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)
    app.jinja_env.filters["local"] = to_local

    init_db()

    app.register_blueprint(auth_bp, url_prefix="/auth")
    app.register_blueprint(user_bp, url_prefix="/user")
    app.register_blueprint(admin_bp, url_prefix="/admin")

    @app.route("/")
    def index():
        return redirect(url_for("auth.login_page"))

    return app


app = create_app()

if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))