import secrets
import hashlib
import base64
import webbrowser
import json
import sys

from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlencode, urlparse, parse_qs
from urllib.request import Request, urlopen
from urllib.error import HTTPError

from config import CLIENT_ID, REDIRECT_URI, SCOPE, AUTHORIZE_ENDPOINT, TOKEN_ENDPOINT

class CallbackHandler(BaseHTTPRequestHandler):

    def do_GET(self):

        parsed_url = urlparse(self.path)
        query_params = parse_qs(parsed_url.query)
        error = query_params.get("error", [None])[0]
        error_description = query_params.get("error_description", [None])[0]

        if error is not None:
            self.send_response(400)
            self.end_headers()
            self.wfile.write(b"Authorization failed.")
            print("OAuth error:", error)
            print("Description:", error_description)
            return
        
        returned_state = query_params.get("state", [None])[0]
        code = query_params.get("code", [None])[0]

        if returned_state != self.server.expected_state:
            self.send_response(400)
            self.end_headers()
            self.wfile.write(b"State validation failed.")
            return
        if code is None:
            self.send_response(400)
            self.end_headers()
            self.wfile.write(b"Authorization code missing.")
            return 
        self.server.authorization_code = code
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"Authentication complete. You can close this tab.")

def create_code_verifier() -> str:
    return secrets.token_urlsafe(64)

def create_code_challenge(code_verifier: str) -> str:
    digest = hashlib.sha256(code_verifier.encode("ascii")).digest()
    return base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")

def create_authorization_url(code_challenge: str, state: str, nonce: str,) -> str:
    params = {
        "client_id": CLIENT_ID,
        "response_type": "code",
        "redirect_uri": REDIRECT_URI,
        "scope": SCOPE,
        "state": state,
        "code_challenge": code_challenge,
        "code_challenge_method": "S256",
        "nonce": nonce,
    }
    return AUTHORIZE_ENDPOINT + "?" + urlencode(params)

def save_session(nonce: str) -> None:
    session_data = {
        "nonce": nonce
    }
    with open("session.json", "w", encoding="utf-8") as f:
        json.dump(session_data, f, indent=4)


def get_authorization_code( authorize_url: str, expected_state: str) -> str | None:
    server = HTTPServer(("localhost", 80), CallbackHandler)

    server.authorization_code = None
    server.expected_state = expected_state

    print("Opening browser for authentication...")
    webbrowser.open(authorize_url)

    print("Waiting for authorization callback...")

    try:
        server.handle_request()
    finally:
        server.server_close()

    return server.authorization_code

def redeem_authorization_code( authorization_code: str, code_verifier: str) -> dict:

    token_data = {
        "client_id": CLIENT_ID,
        "grant_type": "authorization_code",
        "code": authorization_code,
        "redirect_uri": REDIRECT_URI,
        "code_verifier": code_verifier,
    }

    encoded_token_data = urlencode(token_data).encode("ascii")

    headers = {
        "Content-Type": "application/x-www-form-urlencoded"
    }

    request = Request(url=TOKEN_ENDPOINT, headers=headers, data=encoded_token_data, method="POST")

    try:
        response = urlopen(request)
        response_body = response.read()

    except HTTPError as error:
        error_body = error.read().decode("utf-8")
        print("Token request failed:")
        print(error_body)
        raise

    response_text = response_body.decode("utf-8")

    return json.loads(response_text)

def save_token_response(token_response: dict) -> None:
    with open("token_response.json", "w", encoding="utf-8") as f:
        json.dump(token_response, f, indent=4)


def main():
    code_verifier = create_code_verifier()

    state = secrets.token_urlsafe(16)
    nonce = secrets.token_urlsafe(16)

    save_session(nonce)

    code_challenge = create_code_challenge(code_verifier)

    authorize_url = create_authorization_url( code_challenge, state, nonce)

    authorization_code = get_authorization_code(authorize_url, state)

    if authorization_code is None:
        print("Authorization failed. Exiting.")
        sys.exit(1)

    print("Authorization code captured: True")

    try:
        token_response = redeem_authorization_code(authorization_code, code_verifier)
    except HTTPError:
        sys.exit(1)

    save_token_response(token_response)
    print("Token response saved.")


if __name__ == "__main__":
    main()
