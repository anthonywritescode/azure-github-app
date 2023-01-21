from __future__ import annotations

import hmac
import os
import secrets

import azure.functions as func
import flask

flask_app = flask.Flask(__name__)


@flask_app.route('/')
def index() -> str:
    return 'hello hello world'


def _validate_webhook() -> bool:
    signature = flask.request.headers['X-Hub-Signature-256'].replace(
        'sha256=', '',
    )
    body_signature = hmac.new(
        os.environ['GITHUB_WEBHOOK_SECRET'].encode(),
        msg=flask.request.data,
        digestmod='sha256',
    ).hexdigest()
    return secrets.compare_digest(signature, body_signature)


@flask_app.route('/api/github/payload', methods=['POST'])
def github_payload() -> tuple[str, int]:
    if not _validate_webhook():
        return 'invalid signature', 400
    else:
        return '', 204


app = func.WsgiFunctionApp(
    app=flask_app.wsgi_app,
    http_auth_level=func.AuthLevel.ANONYMOUS,
)


def main() -> int:
    flask_app.run()
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
