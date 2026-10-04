
import json
import sys
from datetime import datetime, timezone
from jwt_utils import parse_jwt
from oidc_utils import get_oidc_metadata
from config import CLIENT_ID, CLOCK_SKEW_SECONDS

client_id = "aed91ed2-4921-450d-bf58-3b6726879b5a"


with open("token_response.json", "r", encoding="utf-8") as f:
    token_response = json.load(f)

token = token_response.get("id_token")

if not token:
    print("Valid token not found. Exiting...")
    sys.exit(1)

try:
    header_dict, payload_dict, header, payload, signature = parse_jwt(token)
except ValueError as error:
    print(error)
    sys.exit(1)

metadata = get_oidc_metadata()

expected_issuer = metadata.get("issuer")
token_issuer = payload_dict.get("iss")

# Issuer claim validation
if token_issuer is None:
    print("Issuer claim missing")
    sys.exit(1)
if token_issuer != expected_issuer:
    print("Issuer validation failed")
    sys.exit(1)
print("Issuer validation passed")

# Audience claim validation
aud = payload_dict.get("aud")
if aud is None:
    print("Audience claim missing")
    sys.exit(1)

if isinstance(aud, list):
    if CLIENT_ID not in aud:
        print("Audience validation failed")
        sys.exit(1)
elif isinstance(aud, str):
    if CLIENT_ID != aud:
        print("Audience validation failed")
        sys.exit(1)
else:
    print("Audience claim unexpected type")
print("Audience validation passed")

current_time = datetime.now(timezone.utc).timestamp()
expiry = payload_dict.get("exp")
not_before = payload_dict.get("nbf")
iat = payload_dict.get("iat")

# print(
#     "Current:",
#     datetime.fromtimestamp(current_time, tz=timezone.utc)
# )
# print(
#     "iat:",
#     datetime.fromtimestamp(payload_dict.get("iat"), tz=timezone.utc)
# )
# print(
#     "nbf:",
#     datetime.fromtimestamp(payload_dict.get("nbf"), tz=timezone.utc)
# )
# print(
#     "exp:",
#     datetime.fromtimestamp(payload_dict.get("exp"), tz=timezone.utc)
# )

# Expiration claim validation
if expiry is None:
    print("Expiration claim missing")
    sys.exit(1)

if not isinstance(expiry, (int, float)):
    print("Expiration claim has invalid type")
    sys.exit(1)

current_time = datetime.now(timezone.utc).timestamp()
print("Current time:", current_time)


if current_time >= expiry:
    print("Token expired")
    sys.exit(1)

print("Expiration validation passed")

# Not before claim validation

print("nbf:", not_before)
print("Difference:", not_before - current_time)
if not_before is None:
    print("Not before claim missing")
    sys.exit(1)

if not isinstance(not_before, (int, float)):
    print("Not before claim has invalid type")
    sys.exit(1)

if current_time + CLOCK_SKEW_SECONDS < not_before:
    print("Token not yet valid")
    sys.exit(1)

print("Not_before validation passed")

# Issued at claim validation
if iat is None:
    print("Issued-at claim missing")
    sys.exit(1)

if not isinstance(iat, (int, float)):
    print("Issued-at claim has invalid type")
    sys.exit(1)

if iat  > current_time + CLOCK_SKEW_SECONDS:
    print("Issued-at claim is in the future")
    sys.exit(1)

print("Issued-at validation passed")