import os
import re

import markupsafe
from flask import Flask

from penforge import config
from penforge.web.auth import require_auth
from penforge.web.blueprints.scans import bp as scans_bp
from penforge.web.blueprints.system import bp as system_bp, start_background_threads
from penforge.web.blueprints.osint import bp as osint_bp


def create_app():
    if not config.WEB_PASSWORD:
        raise RuntimeError("WEB_PASSWORD requis : l'interface n'est pas démarrée sans authentification.")

    app = Flask(__name__, template_folder=os.path.join(os.path.dirname(__file__), "templates"))
    app.config["MAX_CONTENT_LENGTH"] = 50 * 1024 * 1024

    @app.template_filter("linkify")
    def linkify_filter(text):
        if not text:
            return markupsafe.Markup("")
        escaped = str(markupsafe.escape(text))
        result = re.sub(
            r'(https?://[^\s<>"\']+)',
            r'<a href="\1" target="_blank" rel="noopener noreferrer">\1</a>',
            escaped,
        )
        return markupsafe.Markup(result)

    app.before_request(require_auth)

    app.register_blueprint(scans_bp)
    app.register_blueprint(system_bp)
    app.register_blueprint(osint_bp)

    start_background_threads()

    return app
