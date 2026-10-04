import base64
import json

# Funtion to base64url encode
def b64url_encode(value: bytes) -> str:
    encoded_value = base64.urlsafe_b64encode(value)
    return encoded_value.decode("ascii").rstrip("=")  

# Function to encode the JWT segment
def encode_jwt_part(segment: dict) -> str:
    encoded_segment_text = json.dumps(segment, separators=(",",":"))
    encoded_segment = encoded_segment_text.encode("utf-8")
    return b64url_encode(encoded_segment)

# Function to base64url decode
def b64url_decode(value: str) -> bytes:
    padding_needed = (-len(value)) % 4
    padded_value = value + "=" * padding_needed
    return base64.urlsafe_b64decode(padded_value)

# Function to decode the JWT segment
def decode_jwt_part(segment: str) -> dict:
    decoded_segment = b64url_decode(segment)
    decoded_segment_text = decoded_segment.decode("utf-8")
    return json.loads(decoded_segment_text)

def parse_jwt(token: str) -> tuple[dict, dict, str, str, str]:
    parts = token.split(".")
    if len(parts) != 3:
        raise ValueError("Invalid JWT format")
    header, payload, signature = parts

    header_dict = decode_jwt_part(header)
    payload_dict = decode_jwt_part(payload)
    
    return header_dict, payload_dict, header, payload, signature