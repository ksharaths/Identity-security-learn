import json

from jwt_utils import parse_jwt
from claims_validation import verify_nonce


with open("token_response.json", "r", encoding="utf-8") as f:
    token_response = json.load(f)

with open("session.json", "r", encoding="utf-8") as f:
    session_data = json.load(f)

token = token_response.get("id_token")
expected_nonce = session_data.get("nonce")

_, payload_dict, _, _, _ = parse_jwt(token)

print("Expected nonce:", expected_nonce)
print("Token nonce:", payload_dict.get("nonce"))
print("Original nonce valid?:", verify_nonce(payload_dict, expected_nonce))

wrong_nonce = "this-is-not-the-original-nonce"

print("Wrong expected nonce:", wrong_nonce)
print("Wrong nonce valid?:", verify_nonce(payload_dict, wrong_nonce))