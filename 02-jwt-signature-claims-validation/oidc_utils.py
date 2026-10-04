import json
from urllib.request import urlopen
from config import AUTHORITY


def get_oidc_metadata() -> dict:
    discovery_url = AUTHORITY.rstrip("/") + "/v2.0/.well-known/openid-configuration"

    response = urlopen(discovery_url)
    return json.loads(response.read().decode("utf-8"))