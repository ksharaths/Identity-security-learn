import json

from jwt_utils import parse_jwt
from signature_validation import verify_signature
from claims_validation import validate_claims
from oidc_utils import get_oidc_metadata


def validate_token(token: str, expected_nonce: str) -> bool:
    if not token:
        return False

    if not verify_signature(token):
        return False

    try:
        _, payload_dict, _, _, _ = parse_jwt(token)
    except ValueError:
        return False

    metadata = get_oidc_metadata()
    expected_issuer = metadata.get("issuer")

    if not validate_claims(
        payload_dict,
        expected_issuer,
        expected_nonce,
    ):
        return False

    return True


if __name__ == "__main__":
    with open("token_response.json", "r", encoding="utf-8") as f:
        token_response = json.load(f)

    with open("session.json", "r", encoding="utf-8") as f:
        session_data = json.load(f)

    token = token_response.get("id_token")
    expected_nonce = session_data.get("nonce")

    valid = validate_token(token, expected_nonce)

    print("Token valid?:", valid)