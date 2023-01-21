from __future__ import annotations

import flask

app = flask.Flask(__name__)


@app.route('/')
def index() -> str:
    return 'hello world'


def main() -> int:
    app.run()
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
