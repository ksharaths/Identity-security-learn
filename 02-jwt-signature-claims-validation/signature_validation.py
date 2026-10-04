import json
import sys
import hashlib
from urllib.request import urlopen
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidSignature
from jwt_utils import b64url_decode, parse_jwt
from oidc_utils import get_oidc_metadata
from config import EXPECTED_ALGORITHM


with open("token_response.json", "r", encoding="utf-8") as f:
    token_response = json.load(f)

token = token_response.get("id_token")

if not token:
    print("Valid token not found. Exiting..")
    sys.exit(1)

try:
    header_dict, payload_dict, header, payload, signature = parse_jwt(token)
except ValueError as error:
    print(error)
    sys.exit(1)

algorithm = header_dict.get("alg")
if algorithm != EXPECTED_ALGORITHM:
    print("Unexpected signing algorithm")
    sys.exit(1)

metadata = get_oidc_metadata()

issuer = payload_dict.get("iss")
expected_issuer = metadata.get("issuer")
if issuer != expected_issuer:
    print("Issuer validation failed")
    sys.exit(1)

jwks_uri = metadata.get("jwks_uri")
response = urlopen(jwks_uri)
jwks_bytes = response.read()
jwks_text = jwks_bytes.decode("utf-8")
jwks = json.loads(jwks_text)

keys = jwks.get("keys")
print("Number of Keys:", len(keys))

matching_key = None
key_id = header_dict.get("kid")
for key in keys:
    if key.get("kid") == key_id:
        matching_key = key
        break

if matching_key:
    print("Matching key found")
else:
    print("Matching key not found")
    sys.exit(1)

exponent_b64 = matching_key.get("e")
exponent_bytes = b64url_decode(exponent_b64)
exponent = int.from_bytes(exponent_bytes, byteorder="big")

modulus_b64 = matching_key.get("n")
modulus_bytes = b64url_decode(modulus_b64)
modulus = int.from_bytes(modulus_bytes, byteorder="big")

signing_input = f"{header}.{payload}".encode("ascii")
signature_bytes = b64url_decode(signature)
signature_int = int.from_bytes(signature_bytes, byteorder="big")

public_numbers = rsa.RSAPublicNumbers(exponent, modulus)
public_key = public_numbers.public_key()
try:
    print("RS256 verification using crypto library")
    public_key.verify(
        signature_bytes,
        signing_input,
        padding.PKCS1v15(),
        hashes.SHA256(),
    )
    print("Signature valid")

except InvalidSignature:
    print("Signature invalid")
    sys.exit(1)

# Manual RS256 verification
print("Manual RS256 verification")
recovered_int = pow(signature_int, exponent, modulus)

key_size_bytes = (modulus.bit_length() + 7) // 8
recovered_bytes = recovered_int.to_bytes(key_size_bytes, byteorder="big")

separator_index = recovered_bytes.find(b"\x00", 2)
digest_info = recovered_bytes[separator_index + 1:]
digest_from_signature = digest_info[-32:]

print("Digest length:", len(digest_from_signature))
print(digest_from_signature.hex())

computed_digest = hashlib.sha256(signing_input).digest()

print("Computed digest length:", len(computed_digest))
print(computed_digest.hex())

print(digest_from_signature == computed_digest)