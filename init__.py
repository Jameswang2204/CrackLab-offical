# cracklab/__init__.py

from flask import Flask

def create_app():
    app = Flask(__name__,
                static_folder='static',
                template_folder='templates')

    # configure your app here e.g. app.config.from_pyfile('../config.py')

    # register your API blueprint
    from .api import api_bp
    app.register_blueprint(api_bp, url_prefix='/api')

    # a catch‑all route to serve your index.html (if using a single‑page UI)
    from flask import render_template
    @app.route('/', defaults={'path': ''})
    @app.route('/<path:path>')
    def catch_all(path):
        return render_template('index.html')

    return app