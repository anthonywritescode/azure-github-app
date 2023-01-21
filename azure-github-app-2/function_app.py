from __future__ import annotations

import base64
import contextlib
import hmac
import json
import os
import secrets
import time
import urllib.request
from collections.abc import Generator
from typing import Any

import azure.functions as func
import flask
import jwt

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


@contextlib.contextmanager
def install_token(install_id: int) -> Generator[str, None, None]:
    payload = {
        'iat': int(time.time()) - 60,
        'exp': int(time.time()) + 5 * 60,
        'iss': int(os.environ['GITHUB_APP_ID']),
    }
    jwt_token = jwt.encode(
        payload,
        base64.b64decode(os.environb[b'GITHUB_PKEY']).decode(),
        algorithm='RS256',
    )
    headers = {'Authorization': f'Bearer {jwt_token}'}

    req = urllib.request.Request(
        f'https://api.github.com/app/installations/{install_id}/access_tokens',
        headers=headers,
        method='POST',
    )
    resp = json.load(urllib.request.urlopen(req))
    try:
        yield resp['token']
    finally:
        req = urllib.request.Request(
            'https://api.github.com/installation/token',
            method='DELETE',
            headers={'Authorization': f'token {resp["token"]}'},
        )
        urllib.request.urlopen(req)


def _issue_comment_created(body: dict[str, Any]) -> None:
    comment = body['comment']['body']
    issue_number = body['issue']['number']
    repo = body['repository']['full_name']
    if 'azure hello hello' in comment:
        with install_token(body['installation']['id']) as token:
            req = urllib.request.Request(
                f'https://api.github.com/repos/{repo}/issues/{issue_number}/comments',  # noqa: E501
                method='POST',
                headers={'Authorization': f'token {token}'},
                data=json.dumps({'body': 'ohai from azure'}).encode(),
            )
            urllib.request.urlopen(req)


@flask_app.route('/api/github/payload', methods=['POST'])
def github_payload() -> tuple[str, int]:
    if not _validate_webhook():
        return 'invalid signature', 400

    body = flask.request.json
    assert body is not None

    event = flask.request.headers['X-Github-Event']
    action = body.get('action')

    if (event, action) == ('issue_comment', 'created'):
        _issue_comment_created(body)

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
