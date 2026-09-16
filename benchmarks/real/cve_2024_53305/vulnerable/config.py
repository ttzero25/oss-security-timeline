import brotli
import pickle
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
        if mode == "u":
            config = pickle.loads(
                brotli.decompress(urlsafe_b64decode(preferences.encode() + b"=="))
            )
        else:
            config = {}
        return config
