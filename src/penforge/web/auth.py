import hmac

from flask import Response, abort, request

from penforge import config


def require_auth():
    auth = request.authorization
    if (
        auth is None
        or not hmac.compare_digest((auth.username or "").encode(), config.WEB_USER.encode())
        or not hmac.compare_digest((auth.password or "").encode(), config.WEB_PASSWORD.encode())
    ):
        return Response("Authentification requise.", 401, {"WWW-Authenticate": 'Basic realm="pentest"'})
    origin = request.headers.get("Origin")
    if request.method == "POST" and origin is not None and origin != request.host_url.rstrip("/"):
        abort(403)
