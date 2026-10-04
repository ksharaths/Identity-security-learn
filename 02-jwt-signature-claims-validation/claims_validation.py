import json
import sys
import secrets
from datetime import datetime, timezone
from jwt_utils import parse_jwt
from oidc_utils import get_oidc_metadata
from config import CLIENT_ID, CLOCK_SKEW_SECONDS

# Nonce validation
def verify_nonce(payload_dict: dict, expected_nonce: str) -> bool:
    # Nonce validation
    token_nonce = payload_dict.get("nonce")

    if expected_nonce is None:
        return False

    if token_nonce is None:
        return False

    if not secrets.compare_digest(token_nonce, expected_nonce):
        return False
    
    return True 

# Issuer claim validation
def verify_issuer(payload_dict: dict, expected_issuer: str) -> bool:
    token_issuer = payload_dict.get("iss")

    if token_issuer is None:
        return False
    if token_issuer != expected_issuer:
        return False
    
    return True

# Audience claim validation
def verify_audience(payload_dict: dict) -> bool:
    aud = payload_dict.get("aud")
    if aud is None:
        return False
    if isinstance(aud, list):
        if CLIENT_ID not in aud:
            return False
    elif isinstance(aud, str):
        if CLIENT_ID != aud:
            return False
    else:
        return False
    
    return True

# Expiration claim validation
def verify_expiry(payload_dict: dict) -> bool:
    current_time = datetime.now(timezone.utc).timestamp()
    expiry = payload_dict.get("exp")
    if expiry is None:
        return False

    if not isinstance(expiry, (int, float)):
        return False

    if current_time - CLOCK_SKEW_SECONDS >= expiry:
        return False

    return True

# Not before claim validation
def verify_not_before(payload_dict: dict) -> bool:
    current_time = datetime.now(timezone.utc).timestamp()
    not_before = payload_dict.get("nbf")
    if not_before is None:
        return False

    if not isinstance(not_before, (int, float)):
        return False

    if current_time + CLOCK_SKEW_SECONDS < not_before:
        return False

    return True

# Issued at claim validation
def verify_issued_at(payload_dict: dict) -> bool:
    current_time = datetime.now(timezone.utc).timestamp()
    iat = payload_dict.get("iat")
    if iat is None:
        return False

    if not isinstance(iat, (int, float)):
        return False

    if iat  > current_time + CLOCK_SKEW_SECONDS:
        return False

    return True

# print(
#     "Current:",
#     datetime.fromtimestamp(current_time, tz=timezone.utc)
# )

def validate_claims(
    payload_dict: dict,
    expected_issuer: str,
    expected_nonce: str,
) -> bool:
    return(
        verify_nonce(payload_dict, expected_nonce)
        and verify_issuer(payload_dict, expected_issuer)
        and verify_audience(payload_dict)
        and verify_expiry(payload_dict)
        and verify_not_before(payload_dict) 
        and verify_issued_at(payload_dict)
    )

if __name__ == "__main__":
    # Load token response
    with open("token_response.json", "r", encoding="utf-8") as f:
        token_response = json.load(f)

    token = token_response.get("id_token")

    if not token:
        print("ID token not found")
        sys.exit(1)

    # Parse token
    try:
        _, payload_dict, _, _, _ = parse_jwt(token)
    except ValueError:
        print("Invalid JWT format")
        sys.exit(1)

    # Load expected nonce
    with open("session.json", "r", encoding="utf-8") as f:
        session_data = json.load(f)

    metadata = get_oidc_metadata()

    expected_issuer = metadata.get("issuer")
    expected_nonce = session_data.get("nonce")

    claims_valid = validate_claims(payload_dict, expected_issuer, expected_nonce)
    print(claims_valid)