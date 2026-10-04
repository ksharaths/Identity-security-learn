import json

from jwt_utils import parse_jwt, encode_jwt_part
from signature_validation import verify_signature


with open("token_response.json", "r", encoding="utf-8") as f:
    token_response = json.load(f)

token = token_response.get("id_token")

header_dict, _, header, payload, signature = parse_jwt(token)

print("Original algorithm:", header_dict.get("alg"))
print("Original token valid?:", verify_signature(token))


header_none = header_dict.copy()
header_none["alg"] = "none"

encoded_none_header = encode_jwt_part(header_none)

none_token = f"{encoded_none_header}.{payload}.{signature}"

print("Modified algorithm:", header_none.get("alg"))
print("alg=none token valid?:", verify_signature(none_token))


header_hs256 = header_dict.copy()
header_hs256["alg"] = "HS256"

encoded_hs256_header = encode_jwt_part(header_hs256)

hs256_token = f"{encoded_hs256_header}.{payload}.{signature}"

print("Modified algorithm:", header_hs256.get("alg"))
print("alg=HS256 token valid?:", verify_signature(hs256_token))