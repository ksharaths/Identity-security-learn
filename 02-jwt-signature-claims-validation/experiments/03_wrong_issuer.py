import json

from jwt_utils import parse_jwt
from claims_validation import verify_issuer
from oidc_utils import get_oidc_metadata


with open("token_response.json", "r", encoding="utf-8") as f:
    token_response = json.load(f)

token = token_response.get("id_token")

_, payload_dict, _, _, _ = parse_jwt(token)

metadata = get_oidc_metadata()
expected_issuer = metadata.get("issuer")

print("Original issuer:", payload_dict.get("iss"))
print("Original valid:", verify_issuer(payload_dict, expected_issuer))

payload_dict["iss"] = "https://evil.example"

print("Modified issuer:", payload_dict.get("iss"))
print("Modified valid:", verify_issuer(payload_dict, expected_issuer))