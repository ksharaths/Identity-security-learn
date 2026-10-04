import json
from urllib.request import urlopen

from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidSignature

from jwt_utils import b64url_decode, parse_jwt
from oidc_utils import get_oidc_metadata
from config import EXPECTED_ALGORITHM


# Fetch JWKS
def get_jwks(jwks_uri: str) -> dict:
    response = urlopen(jwks_uri)
    jwks_bytes = response.read()
    jwks_text = jwks_bytes.decode("utf-8")
    return json.loads(jwks_text)


# Find matching signing key
def find_signing_key(jwks: dict, key_id: str) -> dict | None:
    keys = jwks.get("keys")

    if keys is None:
        return None

    for key in keys:
        if key.get("kid") == key_id:
            return key

    return None


# Build RSA public key from JWK
def build_rsa_public_key(jwk: dict):
    exponent_b64 = jwk.get("e")
    modulus_b64 = jwk.get("n")

    if exponent_b64 is None or modulus_b64 is None:
        return None

    exponent_bytes = b64url_decode(exponent_b64)
    exponent = int.from_bytes(exponent_bytes, byteorder="big")

    modulus_bytes = b64url_decode(modulus_b64)
    modulus = int.from_bytes(modulus_bytes, byteorder="big")

    public_numbers = rsa.RSAPublicNumbers(exponent, modulus)

    return public_numbers.public_key()


# Verify JWT signature
def verify_signature(token: str) -> bool:

    if not token:
        return False

    try:
        header_dict, payload_dict, header, payload, signature = parse_jwt(token)
    except ValueError:
        return False

    algorithm = header_dict.get("alg")

    if algorithm != EXPECTED_ALGORITHM:
        return False

    metadata = get_oidc_metadata()

    issuer = payload_dict.get("iss")
    expected_issuer = metadata.get("issuer")

    if issuer != expected_issuer:
        return False

    jwks_uri = metadata.get("jwks_uri")

    if jwks_uri is None:
        return False

    jwks = get_jwks(jwks_uri)

    key_id = header_dict.get("kid")

    if key_id is None:
        return False

    matching_key = find_signing_key(jwks, key_id)

    if matching_key is None:
        return False

    public_key = build_rsa_public_key(matching_key)

    if public_key is None:
        return False

    signing_input = f"{header}.{payload}".encode("ascii")
    signature_bytes = b64url_decode(signature)

    try:
        public_key.verify(
            signature_bytes,
            signing_input,
            padding.PKCS1v15(),
            hashes.SHA256(),
        )

        return True

    except InvalidSignature:
        return False

# Manual RS256 verification
# print("Manual RS256 verification")
# recovered_int = pow(signature_int, exponent, modulus)

# key_size_bytes = (modulus.bit_length() + 7) // 8
# recovered_bytes = recovered_int.to_bytes(key_size_bytes, byteorder="big")

# separator_index = recovered_bytes.find(b"\x00", 2)
# digest_info = recovered_bytes[separator_index + 1:]
# digest_from_signature = digest_info[-32:]

# print("Digest length:", len(digest_from_signature))
# print(digest_from_signature.hex())

# computed_digest = hashlib.sha256(signing_input).digest()

# print("Computed digest length:", len(computed_digest))
# print(computed_digest.hex())

# print(digest_from_signature == computed_digest)