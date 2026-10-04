import json
from jwt_utils import parse_jwt, encode_jwt_part
from claims_validation import verify_audience

with open("token_response.json", "r", encoding="utf-8") as f:
    token_response = json.load(f)

token = token_response.get("id_token")

header_dict, payload_dict, header, payload, signature = parse_jwt(token)

print("Original aud:", payload_dict.get("aud"))
print("Original valid:", verify_audience(payload_dict))

payload_dict["aud"] = "aed91ed2-4921-450d-bf58-3b6726878b5a"

print("Modified aud:", payload_dict.get("aud"))
print("Modified valid:", verify_audience(payload_dict))