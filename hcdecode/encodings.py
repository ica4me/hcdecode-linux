"""Field representations observed in the supplied legacy HC files."""
import base64
import binascii
import re


def _base64(value: str | bytes) -> bytes:
    if isinstance(value, bytes):
        value = value.decode("ascii")
    value = re.sub(r"\s", "", value)
    if not value or re.fullmatch(r"[A-Za-z0-9+/]*={0,2}", value) is None:
        raise ValueError("Not base64")
    return base64.b64decode(value + "=" * (-len(value) % 4), validate=True)


def _text(value: str) -> bool:
    return bool(value) and sum(c.isprintable() or c in "\r\n\t" for c in value) >= 0.95 * len(value)


def decode_jkl(value: str, key: bytes) -> tuple[str, bool]:
    """Only replace the input after both base64 layers produce readable UTF-8."""
    try:
        first = _base64(value)
        middle = bytes(v ^ key[i % len(key)] for i, v in enumerate(first))
        result = _base64(middle).decode("utf-8")
        if _text(result):
            return result, True
    except (ValueError, UnicodeError, binascii.Error):
        pass
    return value, False


def decode_credentials(value: str, ssh: bool) -> tuple[str, bool]:
    original = value
    # Nibbles in this representation use the first 16 braille alphabet symbols.
    alphabet = "⠁⠃⠉⠙⠑⠋⠛⠓⠊⠚⠅⠇⠍⠝⠕⠏"
    if ssh and value and value[0] in alphabet:
        try:
            value = bytes(
                alphabet.index(value[i]) * 16 + alphabet.index(value[i + 1])
                for i in range(0, len(value), 2)
            ).decode("utf-8")
        except (ValueError, IndexError, UnicodeError):
            return original, False
    pattern = r"^(.+):([\d-]+)@(.+):(.+)$" if ssh else r"^([^:]+):(.+)$"
    match = re.fullmatch(pattern, value)
    if match:
        parts = list(match.groups())
        for i in (-2, -1):
            pairs = re.findall(r"(-?\d+)\.(-?\d+)", parts[i])
            size = len(pairs)
            if not pairs or not all(0 <= int(b) - size <= 63 for _, b in pairs):
                continue
            try:
                result = bytes(
                    ((int(a) - size) // (1 << (int(b) - size))) % 256 for a, b in pairs
                ).decode("utf-8")
                if _text(result):
                    parts[i] = result
            except (UnicodeError, ValueError, OverflowError):
                pass
        value = f"{parts[0]}:{parts[1]}@{parts[2]}:{parts[3]}" if ssh else ":".join(parts)
    return value, value != original
