# /// script
# requires-python = ">=3.13"
# dependencies = [
#     "altair==5.5.0",
#     "marimo",
#     "pandas==2.3.1",
#     "pyarrow",
#     "pyjwt==2.10.1",
#     "requests==2.32.4",
# ]
# ///

# pyright: reportMissingImports=false, reportMissingModuleSource=false

import marimo

__generated_with = "0.14.12"
app = marimo.App(width="medium")


@app.cell(hide_code=True)
def _():
    import base64
    import hashlib
    import http.server
    import json
    import os
    import secrets
    import threading
    import time as t0
    import urllib.parse
    import webbrowser

    import jwt
    import marimo as mo
    import requests

    class LogtoAuth:
        def __init__(self):
            self.LOGTO_ENDPOINT = "https://csy8pa.logto.app/"
            self.CLIENT_ID = "w838u1gcemdzpb7oaeybw"
            self.REDIRECT_URI = "http://localhost:8766/callback"
            self.AUTH_URL = f"{self.LOGTO_ENDPOINT}/oidc/auth"
            self.TOKEN_URL = f"{self.LOGTO_ENDPOINT}/oidc/token"
            self.SCOPES = "openid profile email offline_access"
            self.TOKEN_FILE = f"nxthdr_token_{self.CLIENT_ID}.json"

            # Token storage
            self.access_token = None
            self.id_token = None
            self.refresh_token = None
            self.expires_at = None

        def save_tokens(
            self, access_token=None, id_token=None, refresh_token=None, expires_at=None
        ):
            """Save tokens to file with expiration time"""
            # Use current tokens if not provided
            access_token = access_token or self.access_token
            id_token = id_token or self.id_token
            refresh_token = refresh_token or self.refresh_token

            if expires_at is None:
                # Default to 1 hour from now if not specified
                expires_at = t0.time() + 3600

            token_data = {
                "access_token": access_token,
                "id_token": id_token,
                "refresh_token": refresh_token,
                "expires_at": expires_at,
                "saved_at": t0.time(),
            }

            try:
                with open(self.TOKEN_FILE, "w") as f:
                    json.dump(token_data, f, indent=2)
                print(f"💾 Tokens saved to {self.TOKEN_FILE}")
            except Exception as e:
                print(f"⚠️ Failed to save tokens: {e}")

        def load_tokens(self):
            """Load tokens from file if they exist and are valid"""
            if not os.path.exists(self.TOKEN_FILE):
                return False

            try:
                with open(self.TOKEN_FILE, "r") as f:
                    token_data = json.load(f)

                expires_at = token_data.get("expires_at", 0)
                current_time = t0.time()

                # Check if token is expired (with 5 minute buffer)
                if current_time >= (expires_at - 300):
                    print("🕐 Saved tokens have expired")
                    return False

                self.access_token = token_data.get("access_token")
                self.id_token = token_data.get("id_token")
                self.refresh_token = token_data.get("refresh_token")
                self.expires_at = expires_at

                if self.id_token:
                    # id_token is always a JWT, try to decode it
                    try:
                        claims = jwt.decode(
                            self.id_token, options={"verify_signature": False}
                        )
                        print(
                            f"📂 Loaded valid tokens for {claims.get('email', 'user')}"
                        )
                        print(
                            f"🕐 Token expires in {int((expires_at - current_time) / 60)} minutes"
                        )
                        return True
                    except Exception as e:
                        print(f"⚠️ Saved id_token is invalid: {e}")
                        return False
                else:
                    print("📂 Loaded access token (no id_token available)")
                    return False

            except Exception as e:
                print(f"⚠️ Failed to load tokens: {e}")
                return False

        def do_oauth_flow(self):
            """Perform the OAuth2 PKCE flow"""
            print("🔐 Starting OAuth flow...")

            # PKCE code_verifier and code_challenge
            code_verifier = (
                base64.urlsafe_b64encode(secrets.token_bytes(32)).rstrip(b"=").decode()
            )
            code_challenge = (
                base64.urlsafe_b64encode(
                    hashlib.sha256(code_verifier.encode()).digest()
                )
                .rstrip(b"=")
                .decode()
            )

            # Local server to catch redirect
            class OAuthHandler(http.server.BaseHTTPRequestHandler):
                def do_GET(self):
                    if self.path.startswith("/callback"):
                        parsed = urllib.parse.urlparse(self.path)
                        params = urllib.parse.parse_qs(parsed.query)
                        self.server.auth_code = params.get("code", [None])[0]
                        self.send_response(200)
                        self.end_headers()
                        self.wfile.write(b"Login successful. You may close this tab.")
                    else:
                        self.send_response(404)
                        self.end_headers()

                def log_message(self, format, *args):
                    return  # silence logging

            server = http.server.HTTPServer(("localhost", 8766), OAuthHandler)
            threading.Thread(target=server.serve_forever, daemon=True).start()

            url = (
                f"{self.AUTH_URL}?"
                f"client_id={self.CLIENT_ID}&"
                f"redirect_uri={urllib.parse.quote(self.REDIRECT_URI)}&"
                f"response_type=code&"
                f"scope={urllib.parse.quote(self.SCOPES)}&"
                f"code_challenge_method=S256&"
                f"code_challenge={code_challenge}&"
                f"prompt=consent"
            )
            webbrowser.open(url)
            print("Connecting to nxthdr...")

            # Wait until the server has received the code
            while not hasattr(server, "auth_code"):
                t0.sleep(0.5)

            code = server.auth_code
            server.shutdown()  # stop the HTTP server

            # Now exchange it for tokens
            data = {
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": self.REDIRECT_URI,
                "client_id": self.CLIENT_ID,
                "code_verifier": code_verifier,
            }

            response = requests.post(self.TOKEN_URL, data=data)
            tokens = response.json()

            self.access_token = tokens.get("access_token")
            self.id_token = tokens.get("id_token")
            self.refresh_token = tokens.get("refresh_token")
            expires_in = tokens.get("expires_in", 3600)  # Default to 1 hour
            self.expires_at = t0.time() + expires_in

            # Use access_token for API calls, id_token for user info
            claims = jwt.decode(self.id_token, options={"verify_signature": False})
            print(f"You are now connected with {claims['email']}")

            if not self.refresh_token:
                print(
                    "⚠️  No refresh token received - you'll need to re-authenticate when the token expires"
                )

            # Save tokens to file
            self.save_tokens(expires_at=self.expires_at)

        def refresh_access_token(self):
            """Refresh the access token using the refresh token"""
            if not self.refresh_token:
                print("❌ No refresh token available. Please re-authenticate.")
                return False

            data = {
                "grant_type": "refresh_token",
                "refresh_token": self.refresh_token,
                "client_id": self.CLIENT_ID,
            }

            response = requests.post(self.TOKEN_URL, data=data)
            if response.status_code == 200:
                tokens = response.json()
                # Update the stored tokens
                self.access_token = tokens.get("access_token")
                self.id_token = tokens.get("id_token")
                new_refresh_token = tokens.get("refresh_token")
                if new_refresh_token:  # Only update if a new refresh token is provided
                    self.refresh_token = new_refresh_token

                print("✅ Token refreshed successfully!")
                print(f"New access token: {self.access_token[:20]}...")

                # Save refreshed tokens to file
                expires_in = tokens.get("expires_in", 3600)
                self.expires_at = t0.time() + expires_in
                self.save_tokens(expires_at=self.expires_at)
                return True
            else:
                print(
                    f"❌ Failed to refresh token: {response.status_code} - {response.text}"
                )
                return False

        def clear_saved_tokens(self):
            """Clear saved tokens file"""
            try:
                if os.path.exists(self.TOKEN_FILE):
                    os.remove(self.TOKEN_FILE)
                    print("🗑️ Saved tokens cleared")
                else:
                    print("ℹ️ No saved tokens to clear")
            except Exception as e:
                print(f"❌ Failed to clear tokens: {e}")

        def authenticate(self):
            """Main authentication method - try to load tokens or do OAuth flow"""
            if self.load_tokens():
                print("✅ Using saved tokens - skipping OAuth flow")
                return True
            else:
                self.do_oauth_flow()
                return True

    # Create and authenticate
    auth = LogtoAuth()
    auth.authenticate()

    mo.md(f"""
    ## 🔐 Authentication Status
    {"**You are authenticated!**" if auth.access_token else "**You are not authenticated!**"}
    """)

    return auth, mo, requests


@app.cell(hide_code=True)
def _(auth, mo):
    def refresh_token_handler():
        """Handle refresh token button click"""
        auth.refresh_access_token()

    def clear_tokens_handler():
        """Handle clear tokens button click"""
        auth.clear_saved_tokens()

    refresh_button = mo.ui.button(
        label="🔄 Refresh Token",
        on_click=lambda _: refresh_token_handler(),
        kind="success",
        disabled=not auth.refresh_token,  # Disable if no refresh token
    )

    clear_button = mo.ui.button(
        label="🗑️ Clear Saved Tokens",
        on_click=lambda _: clear_tokens_handler(),
        kind="warn",
    )

    mo.md(f"""
    ## 🔐 Token Management

    Tokens are automatically saved to `nxthdr_tokens.json` and will be loaded on next restart if still valid.

    {refresh_button if auth.refresh_token else mo.md("*Refresh not available - no refresh token received from the server.*")}

    {clear_button}
    """)
    return


@app.cell(hide_code=True)
def _(auth, mo, requests):
    user_info = requests.get(
        "https://nxthdr.dev/api/user/me",
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {auth.id_token}",
        },
    ).json()

    mo.md(f"""
    ## 💳 User Credits

    ```
    {user_info["used"]:} / {user_info["limit"]:}
    ```
    """)
    return


@app.cell(hide_code=True)
def _(mo):
    mo.md(r"""---""")
    return


@app.cell
def _(auth, requests):
    import ipaddress

    user_prefixes = requests.get(
        "https://nxthdr.dev/api/user/prefixes",
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {auth.id_token}",
        },
    ).json()

    metadata = []
    for a in user_prefixes["agents"]:
        ip_address = str(
            next(ipaddress.ip_network(a["prefixes"][0]["user_prefix"]).hosts())
        )
        metadata.append({"id": a["agent_id"], "ip_address": ip_address})

    requests.post(
        "https://nxthdr.dev/api/probes",
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {auth.id_token}",
        },
        json={
            "metadata": metadata,
            "probes": [
                ["2606:4700:4700::1111", 24000, 33434, 30, "icmpv6"],
                ["2606:4700:4700::1001", 24000, 33434, 30, "udp"],
                ["2001:4860:4860::8888", 24000, 33434, 30, "icmpv6"],
                ["2001:4860:4860::8844", 24000, 33434, 30, "udp"],
            ],
        },
    ).json()
    return (metadata,)


@app.cell
def _(metadata, mo, requests):
    from io import StringIO

    import pandas as pd
    from requests.auth import HTTPBasicAuth

    # Construct source IP filter
    src_ip_filter = "".join(
        set([f"AND probe_src_addr = toIPv6('{m['ip_address']}')" for m in metadata])
    )

    query = f"""
    SELECT
      time_received_ns,
      probe_src_addr,
      probe_dst_addr,
      probe_protocol,
      probe_ttl,
      reply_src_addr
    FROM saimiris.replies
    WHERE
      time_received_ns >= now() - INTERVAL 1 HOUR
      {src_ip_filter}
    ORDER BY time_received_ns DESC
    FORMAT CSVWithNames
    """

    res = requests.post(
        "https://nxthdr.dev/api/query/",
        headers={"Content-Type": "text/plain"},
        auth=HTTPBasicAuth("read", "read"),
        data=query.strip(),
    )

    df = pd.read_csv(StringIO(res.text))
    mo.ui.table(
        data=df,
        pagination=True,
        label="Dataframe",
    )
    return


if __name__ == "__main__":
    app.run()
