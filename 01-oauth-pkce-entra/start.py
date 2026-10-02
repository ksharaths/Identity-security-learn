# Generates a fresh PKCE verifier, state and nonce, and prints the
# authorize URL. Replace CLIENT_ID with your app registration's
# Application (client) ID before running. Redemption is done manually
# with curl.exe (see README, section 6).


import secrets
import hashlib
import base64
from urllib.parse import urlencode

CLIENT_ID = "<CLIENT_ID>"

code_verifier = secrets.token_urlsafe(64)
state = secrets.token_urlsafe(16)
nonce = secrets.token_urlsafe(16)

digest = hashlib.sha256(code_verifier.encode("ascii")).digest()
code_challenge = base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")

params = {
    "client_id": CLIENT_ID,
    "response_type": "code",
    "redirect_uri": "http://localhost",
    "scope": "openid offline_access User.Read",
    "state": state,
    "code_challenge": code_challenge,
    "code_challenge_method": "S256",
    "nonce": nonce,
}

print("code_verifier:", code_verifier)
print("state:", state)
print("nonce:", nonce)
print()
print("https://login.microsoftonline.com/consumers/oauth2/v2.0/authorize?" + urlencode(params))
