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
        elif code is None:
            self.send_response(400)
            self.end_headers()
            self.wfile.write(b"Authorization code missing.")
            return 
        else:
            self.server.authorization_code = code
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"Authentication complete. You can close this tab.")

code_verifier = secrets.token_urlsafe(64)
state = secrets.token_urlsafe(16)
nonce = secrets.token_urlsafe(16)

session_data = {
    "nonce": nonce
}

with open("session.json", "w", encoding="UTF-8") as f:
    json.dump( session_data, f, indent=4)

digest = hashlib.sha256(code_verifier.encode("ascii")).digest()
code_challenge = base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")

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

authorize_url = AUTHORIZE_ENDPOINT + "?" + urlencode(params)

server = HTTPServer(("localhost", 80), CallbackHandler)
server.authorization_code = None
server.expected_state = state

print("Opening browser for authentication...")
webbrowser.open(authorize_url)

print("Waiting for authorization callback...")
server.handle_request()
server.server_close()
if server.authorization_code is None:
    print("Authorization failed. Exiting.")
    sys.exit(1)

if server.authorization_code:
    print("Authorization code captured: True")

token_data = {
    "client_id": CLIENT_ID,
    "grant_type": "authorization_code",
    "code": server.authorization_code,
    "redirect_uri": REDIRECT_URI,
    "code_verifier": code_verifier,
}
encoded_token_data = urlencode(token_data).encode("ascii")

headers={"Content-Type": "application/x-www-form-urlencoded"}
request = Request(url=TOKEN_ENDPOINT, headers=headers, data=encoded_token_data, method="POST")

try:
    response = urlopen(request)
    response_body = response.read()

except HTTPError as error:
    error_body = error.read().decode("utf-8")
    print("Token request failed:")
    print(error_body)
    sys.exit(1)

response_text = response_body.decode("utf-8")
token_response = json.loads(response_text)

with open("token_response.json", "w", encoding="utf-8") as f:
    json.dump(token_response, f, indent=4)