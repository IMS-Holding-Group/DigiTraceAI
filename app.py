from werkzeug.serving import WSGIRequestHandler

from app import create_app
from app.config import HOST, PORT
from app.database import init_db


class QuietHandler(WSGIRequestHandler):
    def version_string(self):
        return "web"


def main():
    init_db()
    application = create_app()
    application.run(host=HOST, port=PORT, debug=False, use_reloader=False, request_handler=QuietHandler)


if __name__ == "__main__":
    main()
