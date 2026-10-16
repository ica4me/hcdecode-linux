"""Separate display policy from the lossless, in-memory decoding API."""
from copy import deepcopy
import hashlib
import re

from .errors import DecodeError

SECRET_KEYS = {"id", "uuid", "password", "username", "user", "email", "token", "privatekey", "secret"}


def render(decoded: dict, *, show_secrets: bool = False, v2ray_only: bool = False) -> dict:
    result = deepcopy(decoded)
    if not show_secrets:
        known_secrets = set()

        def tree(obj):
            if isinstance(obj, dict):
                for key, value in obj.items():
                    if key.lower() in SECRET_KEYS and isinstance(value, str) and value:
                        known_secrets.add(value)
                        obj[key] = "[REDACTED]"
                    else:
                        tree(value)
            elif isinstance(obj, list):
                for value in obj:
                    tree(value)

        tree(result["connection"])
        for field in result["fields"]:
            index, value = field["index"], field["value"]
            if index == 6:
                field["original_characters"] = len(value)
                field["original_sha256"] = hashlib.sha256(value.encode()).hexdigest()
                field["value"] = "[NOTES OMITTED]" if value else ""
            elif index in {7, 11} and value:
                field["value"] = "[CREDENTIALS REDACTED]"
            elif index == 26 and value:
                field["value"] = deepcopy(result["connection"]["v2ray"])

        def scrub(obj):
            if isinstance(obj, str):
                if obj in known_secrets:
                    return "[REDACTED]"
                # Also redact copies embedded in payloads/URLs, without replacing single letters.
                for secret in sorted(known_secrets, key=len, reverse=True):
                    if len(secret) >= 4:
                        obj = obj.replace(secret, "[REDACTED]")
                return re.sub(r"https?://wa\.me/\d+", "https://wa.me/[REDACTED]", obj)
            if isinstance(obj, dict):
                return {k: scrub(v) for k, v in obj.items()}
            if isinstance(obj, list):
                return [scrub(v) for v in obj]
            return obj

        result = scrub(result)
    if v2ray_only:
        if "v2ray" not in result["connection"]:
            raise DecodeError("File ini tidak memiliki JSON V2Ray")
        return result["connection"]["v2ray"]
    result["redacted"] = not show_secrets
    return result
