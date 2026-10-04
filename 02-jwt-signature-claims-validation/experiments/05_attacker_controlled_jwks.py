import json

from jwt_utils import parse_jwt
from oidc_utils import get_oidc_metadata
from claims_validation import verify_issuer


with open("token_response.json", "r", encoding="utf-8") as f:
    token_response = json.load(f)

token = token_response.get("id_token")

_, payload_dict, _, _, _ = parse_jwt(token)

metadata = get_oidc_metadata()
expected_issuer = metadata.get("issuer")

print("Trusted expected issuer:", expected_issuer)
print("Original token issuer:", payload_dict.get("iss"))
print("Original issuer valid:", verify_issuer(payload_dict, expected_issuer))

payload_dict["iss"] = "https://evil.example"

print("Attacker-controlled issuer:", payload_dict.get("iss"))
print("Attacker issuer valid:", verify_issuer(payload_dict, expected_issuer))

old_discovery_url = (
    payload_dict["iss"].rstrip("/")
    + "/.well-known/openid-configuration"
)

old_discovery_url = (
    payload_dict["iss"].rstrip("/")
    + "/.well-known/openid-configuration"
)

print("Metadata derived from the token would fetch:", old_discovery_url)