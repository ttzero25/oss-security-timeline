import brotli
import json
from base64 import urlsafe_b64decode


class Config:
    def from_params(self, params) -> "Config":
        if "preferences" in params:
            params_new = self._decode_preferences(params["preferences"])
            if len(params_new):
                params = params_new
        return self

    def _decode_preferences(self, preferences: str) -> dict:
        mode = preferences[0]
        preferences = preferences[1:]
        try:
            decoded_data = brotli.decompress(
                urlsafe_b64decode(preferences.encode() + b"==")
            )
            config = json.loads(decoded_data)
        except Exception:
            config = {}
        return config
