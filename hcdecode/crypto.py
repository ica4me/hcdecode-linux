"""Original 64-bit-nonce ChaCha20-Poly1305, with empty associated data.

Do not substitute Crypto.Cipher.ChaCha20_Poly1305: its MAC layout differs.
No encryption API is offered; the fixed nonce is a legacy input property.
"""
import re
import struct

from Crypto.Cipher import ChaCha20
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.poly1305 import Poly1305

from .errors import AuthenticationError, DecodeError


def open_record(value: str, key: bytes, nonce: bytes, label: str) -> str:
    if not isinstance(value, str) or len(value) < 32 or len(value) % 2:
        raise DecodeError(f"{label}: record heksadesimal tidak lengkap")
    if re.fullmatch(r"[0-9a-fA-F]+", value) is None:
        raise DecodeError(f"{label}: record bukan heksadesimal")
    record = bytes.fromhex(value)
    ciphertext, tag = record[:-16], record[-16:]
    cipher = ChaCha20.new(key=key, nonce=nonce)
    one_time_key = cipher.encrypt(bytes(32))
    authenticated = bytes(8) + ciphertext + struct.pack("<Q", len(ciphertext))
    try:
        Poly1305.verify_tag(one_time_key, authenticated, tag)
    except InvalidSignature as exc:
        raise AuthenticationError(
            f"{label}: tag tidak valid; file rusak atau profil/kunci/nonce tidak cocok"
        ) from exc
    cipher.seek(64)
    try:
        # ChaCha XOR is symmetric; keep the same API direction after generating the OTK.
        return cipher.encrypt(ciphertext).decode("utf-8")
    except UnicodeDecodeError as exc:
        raise DecodeError(f"{label}: plaintext terautentikasi bukan UTF-8") from exc
