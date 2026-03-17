from flask import Flask, request, render_template_string
import threading
import werkzeug.serving
import logging

# Disable Flask's default logging to keep the console clean for your prints
log = logging.getLogger("werkzeug")
log.setLevel(logging.ERROR)


class VulnerableWebServer:
    def __init__(self, port=8080):
        self.app = Flask(__name__)
        self.port = port
        self.server = None
        self.thread = None

        # Template for the simulated login
        self.login_template = """
        <!DOCTYPE html>
        <html>
        <head>
            <title>University Network - Login</title>
            <style>
                body { font-family: sans-serif; display: flex; justify-content: center; padding-top: 50px; background: #f0f2f5; }
                .card { background: white; padding: 2rem; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
                input { display: block; margin: 10px 0; padding: 8px; width: 200px; }
                button { width: 100%; padding: 10px; background: #007bff; color: white; border: none; border-radius: 4px; cursor: pointer; }
            </style>
        </head>
        <body>
            <div class="card">
                <h2>Campus Wi-Fi</h2>
                <p>Please sign in to continue</p>
                <form method="POST" action="/login">
                    <input type="text" name="username" placeholder="Username" required>
                    <input type="password" name="password" placeholder="Password" required>
                    <button type="submit">Sign In</button>
                </form>
            </div>
        </body>
        </html>
        """

        @self.app.route("/")
        def index():
            return render_template_string(self.login_template)

        @self.app.route("/login", methods=["POST"])
        def login():
            # In a real vulnerability demo, Wireshark will see these keys/values
            # because they are sent in an unencrypted HTTP POST body.
            captured_data = request.form.to_dict()

            # Print to terminal so you can verify the "attack" worked
            print(f"\n[!] DEMO LOG: Received Submission: {captured_data}")

            return """
            <div style="text-align:center; margin-top:50px;">
                <h2 style="color: green;">Successfully Connected!</h2>
                <p>You are now authorized to use the campus network.</p>
            </div>
            """

    def start(self):
        """Starts the server in a background thread."""
        if self.thread is not None:
            return

        self.server = werkzeug.serving.make_server("0.0.0.0", self.port, self.app)
        self.thread = threading.Thread(target=self.server.serve_forever)
        self.thread.daemon = True
        self.thread.start()
        print(f"[*] Vulnerable Web Server started on port {self.port} (HTTP)")

    def stop(self):
        """Stops the server."""
        if self.server:
            self.server.shutdown()
            self.thread.join()
            self.server = None
            self.thread = None
            print("[*] Vulnerable Web Server stopped.")


if __name__ == "__main__":
    # For standalone testing
    import time

    server = VulnerableWebServer()
    server.start()
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        server.stop()
