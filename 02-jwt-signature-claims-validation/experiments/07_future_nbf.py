import json
from datetime import datetime, timezone

from jwt_utils import parse_jwt
from claims_validation import verify_not_before
from config import CLOCK_SKEW_SECONDS


with open("token_response.json", "r", encoding="utf-8") as f:
    token_response = json.load(f)

token = token_response.get("id_token")

_, payload_dict, _, _, _ = parse_jwt(token)

print("Original nbf:", payload_dict.get("nbf"))
print("Original nbf valid?:", verify_not_before(payload_dict))

current_time = datetime.now(timezone.utc).timestamp()

payload_dict["nbf"] = current_time + CLOCK_SKEW_SECONDS + 300

print("Tampered nbf:", payload_dict.get("nbf"))
print("Future nbf valid?:", verify_not_before(payload_dict))