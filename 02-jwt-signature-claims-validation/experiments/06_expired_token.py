import json
from datetime import datetime, timezone

from jwt_utils import parse_jwt
from claims_validation import verify_expiry
from config import CLOCK_SKEW_SECONDS


with open("token_response.json", "r", encoding="utf-8") as f:
    token_response = json.load(f)

token = token_response.get("id_token")

_, payload_dict, _, _, _ = parse_jwt(token)

print("Original exp:", payload_dict.get("exp"))
print("Original expiry valid?:", verify_expiry(payload_dict))

current_time = datetime.now(timezone.utc).timestamp()

payload_dict["exp"] = current_time - CLOCK_SKEW_SECONDS - 60

print("Tampered exp:", payload_dict.get("exp"))
print("Expired token valid?:", verify_expiry(payload_dict))