from __future__ import annotations

import azure.functions as func
import flask

flask_app = flask.Flask(__name__)


@flask_app.route('/')
def index() -> str:
    return 'hello hello world'


app = func.WsgiFunctionApp(
    app=flask_app.wsgi_app,
    http_auth_level=func.AuthLevel.ANONYMOUS,
)


def main() -> int:
    flask_app.run()
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
