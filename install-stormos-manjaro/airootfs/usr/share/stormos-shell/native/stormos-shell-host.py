#!/usr/bin/env python3
import http.server
import os
import socket
import socketserver
import sys
import threading
from pathlib import Path

import gi

gi.require_version("Gtk", "4.0")
gi.require_version("WebKit", "6.0")
from gi.repository import Gtk, WebKit

DIST_DIR = Path("/usr/share/stormos-shell/dist").resolve()


class QuietHandler(http.server.SimpleHTTPRequestHandler):
    def log_message(self, fmt, *args):
        pass

    def end_headers(self):
        self.send_header("Cache-Control", "no-store")
        super().end_headers()


def start_local_server():
    handler = lambda *args, **kwargs: QuietHandler(*args, directory=str(DIST_DIR), **kwargs)
    server = socketserver.ThreadingTCPServer(("127.0.0.1", 0), handler)
    server.daemon_threads = True
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server


class StormOSApplication(Gtk.Application):
    def __init__(self):
        super().__init__(application_id="org.stormos.DesktopShell")
        self.server = None

    def do_activate(self):
        self.server = start_local_server()
        port = self.server.server_address[1]

        window = Gtk.ApplicationWindow(application=self)
        window.set_title("StormOS")
        window.set_default_size(1440, 900)
        window.set_decorated(False)

        webview = WebKit.WebView()
        settings = webview.get_settings()
        settings.set_enable_developer_extras(False)
        settings.set_enable_javascript(True)
        settings.set_enable_webgl(True)
        settings.set_allow_file_access_from_file_urls(False)
        settings.set_allow_universal_access_from_file_urls(False)
        webview.load_uri(f"http://127.0.0.1:{port}/")

        window.set_child(webview)
        window.fullscreen()
        window.present()

    def do_shutdown(self):
        if self.server is not None:
            self.server.shutdown()
            self.server.server_close()
        Gtk.Application.do_shutdown(self)


if __name__ == "__main__":
    if not DIST_DIR.is_dir() or not (DIST_DIR / "index.html").is_file():
        print(f"Missing desktop bundle: {DIST_DIR}/index.html", file=sys.stderr)
        sys.exit(1)
    raise SystemExit(StormOSApplication().run(sys.argv))
