import json
from jwt_utils import parse_jwt, encode_jwt_part
from signature_validation import verify_signature

with open("token_response.json", "r", encoding="utf-8") as f:
    token_response = json.load(f)

token = token_response.get("id_token")

header_dict, payload_dict, header, payload, signature = parse_jwt(token)

payload_dict["name"] = "Tampered User"

modified_payload = encode_jwt_part(payload_dict)

tampered_token = f"{header}.{modified_payload}.{signature}"


print(verify_signature(token))
print(verify_signature(tampered_token))