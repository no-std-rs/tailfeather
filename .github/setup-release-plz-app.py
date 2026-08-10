#!/usr/bin/env python3
"""Create and install Tailfeather's release-plz GitHub App from a manifest.

Generated credentials stay in memory and are sent to `gh secret set` over
stdin. Run this script from a trusted workstation with an authenticated GitHub
CLI, then follow the capability URL it prints.
"""

import argparse
import html
import json
import secrets
import subprocess
import threading
import urllib.error
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


REPOSITORY = "pawelchcki/tailfeather"
STATE = secrets.token_urlsafe(32)
FLOW_TOKEN = secrets.token_urlsafe(32)
FLOW_PATH = f"/{FLOW_TOKEN}"
SERVER = None
APP_SLUG = None
PENDING_CREDENTIALS = None


def page(title, body):
    return f"""<!doctype html>
<html lang="en">
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{html.escape(title)}</title>
<style>
body {{ font: 16px/1.5 system-ui, sans-serif; max-width: 48rem; margin: 4rem auto; padding: 0 1rem; }}
button, a.button {{ display: inline-block; padding: .7rem 1rem; border: 0; border-radius: .35rem; background: #1f883d; color: white; font-weight: 600; text-decoration: none; cursor: pointer; }}
code {{ background: #f3f4f6; padding: .15rem .3rem; border-radius: .25rem; }}
li {{ margin: .35rem 0; }}
</style>
<h1>{html.escape(title)}</h1>
{body}
</html>"""


def set_repository_secret(name, value):
    result = subprocess.run(
        ["gh", "secret", "set", name, "--repo", REPOSITORY],
        input=value.encode(),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if result.returncode != 0:
        message = result.stderr.decode(errors="replace").strip()
        raise RuntimeError(f"gh secret set {name} failed: {message}")


def install_credentials():
    global PENDING_CREDENTIALS
    if not PENDING_CREDENTIALS:
        return
    set_repository_secret(
        "RELEASE_PLZ_APP_CLIENT_ID", PENDING_CREDENTIALS["client_id"]
    )
    set_repository_secret(
        "RELEASE_PLZ_APP_PRIVATE_KEY", PENDING_CREDENTIALS["pem"]
    )
    PENDING_CREDENTIALS = None


def request_base_url(handler):
    host = handler.headers.get("Host", "")
    try:
        parsed = urllib.parse.urlsplit(f"http://{host}")
        port = parsed.port
    except ValueError as error:
        raise RuntimeError("invalid Host header") from error
    if (
        not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path
        or parsed.query
        or parsed.fragment
        or (port is not None and not 1 <= port <= 65535)
    ):
        raise RuntimeError("invalid Host header")
    return f"http://{host}{FLOW_PATH}"


def manifest_for(base_url):
    return {
        "name": "tailfeather-release-plz",
        "url": "https://github.com/pawelchcki/tailfeather",
        "redirect_url": f"{base_url}/callback",
        "setup_url": f"{base_url}/installed",
        "description": "Creates release-plz pull requests, tags, and GitHub releases for Tailfeather.",
        "public": False,
        "default_permissions": {
            "contents": "write",
            "pull_requests": "write",
        },
        "default_events": [],
        "request_oauth_on_install": False,
        "setup_on_update": False,
    }


class Handler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        # Keep callback codes and query strings out of terminal logs.
        return

    def send_html(self, status, content):
        encoded = content.encode()
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(encoded)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header(
            "Content-Security-Policy",
            "default-src 'none'; style-src 'unsafe-inline'; form-action https://github.com",
        )
        self.end_headers()
        self.wfile.write(encoded)

    def do_GET(self):
        route = urllib.parse.urlparse(self.path)
        if route.path == f"{FLOW_PATH}/":
            try:
                base_url = request_base_url(self)
            except RuntimeError as error:
                self.send_html(400, page("Invalid request", f"<p>{html.escape(str(error))}</p>"))
                return
            manifest = html.escape(json.dumps(manifest_for(base_url)), quote=True)
            action = f"https://github.com/settings/apps/new?state={urllib.parse.quote(STATE)}"
            body = f"""
<p>This creates a private, repository-scoped release App owned by your personal GitHub account.</p>
<ul>
  <li>Contents: read and write</li>
  <li>Pull requests: read and write</li>
  <li>No webhooks</li>
  <li>No OAuth user authorization</li>
</ul>
<form action="{action}" method="post">
  <input type="hidden" name="manifest" value="{manifest}">
  <button type="submit">Create the GitHub App</button>
</form>
"""
            self.send_html(200, page("Tailfeather release App", body))
            return

        if route.path == f"{FLOW_PATH}/callback":
            self.handle_callback(urllib.parse.parse_qs(route.query))
            return

        if route.path == f"{FLOW_PATH}/retry-secrets":
            try:
                install_credentials()
            except Exception as error:
                self.send_html(
                    500,
                    page(
                        "Secret setup failed",
                        f"<p>{html.escape(str(error))}</p><p><a class=\"button\" href=\"{FLOW_PATH}/retry-secrets\">Retry</a></p>",
                    ),
                )
                return
            self.show_install_page()
            return

        if route.path == f"{FLOW_PATH}/installed":
            params = urllib.parse.parse_qs(route.query)
            installation_id = params.get("installation_id", ["unknown"])[0]
            body = f"""
<p>The App was installed and both repository secrets were configured.</p>
<p>Installation ID: <code>{html.escape(installation_id)}</code></p>
<p>You can close this tab. Publishing remains disabled until the crates.io bootstrap is complete.</p>
"""
            self.send_html(200, page("GitHub App setup complete", body))
            threading.Timer(2, SERVER.shutdown).start()
            return

        self.send_html(404, page("Not found", "<p>This one-off route does not exist.</p>"))

    def handle_callback(self, params):
        global APP_SLUG, PENDING_CREDENTIALS
        state = params.get("state", [None])[0]
        code = params.get("code", [None])[0]
        if not secrets.compare_digest(state or "", STATE) or not code:
            self.send_html(400, page("Invalid callback", "<p>The state or manifest code is invalid.</p>"))
            return

        request = urllib.request.Request(
            f"https://api.github.com/app-manifests/{urllib.parse.quote(code)}/conversions",
            data=b"",
            method="POST",
            headers={
                "Accept": "application/vnd.github+json",
                "X-GitHub-Api-Version": "2022-11-28",
                "User-Agent": "tailfeather-release-app-bootstrap/1",
            },
        )
        try:
            with urllib.request.urlopen(request, timeout=30) as response:
                app = json.load(response)
            APP_SLUG = app["slug"]
            PENDING_CREDENTIALS = {
                "client_id": app["client_id"],
                "pem": app["pem"],
            }
            install_credentials()
        except urllib.error.HTTPError as error:
            detail = error.read().decode(errors="replace")
            self.send_html(
                502,
                page(
                    "Manifest exchange failed",
                    f"<p>GitHub returned HTTP {error.code}: {html.escape(detail)}</p>",
                ),
            )
            return
        except Exception as error:
            self.send_html(
                500,
                page(
                    "Secret setup failed",
                    f"<p>{html.escape(str(error))}</p><p>The generated credentials remain only in this process.</p><p><a class=\"button\" href=\"{FLOW_PATH}/retry-secrets\">Retry</a></p>",
                ),
            )
            return

        self.show_install_page()

    def show_install_page(self):
        install_url = f"https://github.com/apps/{urllib.parse.quote(APP_SLUG)}/installations/new"
        body = f"""
<p>The App was created and its credentials were stored as repository secrets.</p>
<p>Install it next. Choose <strong>Only select repositories</strong>, then select <code>tailfeather</code>.</p>
<p><a class="button" href="{install_url}">Install the App</a></p>
"""
        self.send_html(200, page("Credentials configured", body))


parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument(
    "--listen",
    default="127.0.0.1",
    help="address to bind (default: 127.0.0.1)",
)
parser.add_argument(
    "--port",
    default=0,
    type=int,
    help="port to bind; zero chooses an unused port (default: 0)",
)
args = parser.parse_args()

SERVER = ThreadingHTTPServer((args.listen, args.port), Handler)
port = SERVER.server_address[1]
print(f"LISTENING {args.listen}:{port}", flush=True)
print(f"OPEN http://<reachable-host>:{port}{FLOW_PATH}/", flush=True)
SERVER.serve_forever()
SERVER.server_close()
print("COMPLETE", flush=True)
