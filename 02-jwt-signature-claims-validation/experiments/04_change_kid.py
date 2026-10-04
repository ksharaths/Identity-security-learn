import json

from jwt_utils import parse_jwt, encode_jwt_part
from signature_validation import verify_signature


with open("token_response.json", "r", encoding="utf-8") as f:
    token_response = json.load(f)

token = token_response.get("id_token")

header_dict, _, _, payload, signature = parse_jwt(token)

print("Original kid:", header_dict.get("kid"))
print("Original header valid?:", verify_signature(token))

header_dict["kid"] = "sbkjnsafjnsaf9"
print("Tampered kid:", header_dict.get("kid"))

modified_header = encode_jwt_part(header_dict)

token = f"{modified_header}.{payload}.{signature}"

print("Original kid:", header_dict.get("kid"))
print("Tampered header valid?:", verify_signature(token))

