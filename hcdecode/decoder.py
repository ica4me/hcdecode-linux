"""Authenticate the envelope and fields, then preserve the complete configuration."""
import hashlib
import json
from pathlib import Path
import re

from .crypto import open_record
from .encodings import decode_credentials, decode_jkl
from .errors import DecodeError, UnsupportedFormat
from .profile import LEGACY_AB, Profile

LABELS = {
    0: "payload", 1: "remote_proxy", 4: "config_expiry", 5: "notes_enabled",
    6: "notes_html", 7: "ssh_account", 10: "openvpn_config", 11: "openvpn_credentials",
    12: "tls_sni", 18: "config_name", 20: "connection_mode_raw", 24: "psiphon_fields",
    25: "v2ray_enabled", 26: "v2ray_config", 27: "config_version_raw",
    28: "slowdns_enabled", 29: "slowdns_server", 30: "slowdns_public_key", 31: "dns_resolver",
}


def _object(text: str, label: str) -> dict:
    try:
        obj = json.loads(text)
    except (ValueError, RecursionError) as exc:
        raise DecodeError(f"{label}: JSON tidak valid") from exc
    if not isinstance(obj, dict):
        raise DecodeError(f"{label}: objek JSON diperlukan")
    return obj


def decode_bytes(raw: bytes, *, source: str = "<bytes>", profile: Profile = LEGACY_AB) -> dict:
    """Return original plaintext in memory. Use reporting.render() before displaying it."""
    if not raw or len(raw) > profile.max_input_bytes:
        raise DecodeError("Ukuran input kosong atau melebihi batas 16 MiB")
    try:
        latin = raw.decode("utf-8").encode("latin1")
        encoded = bytes(v ^ profile.outer_xor[i % len(profile.outer_xor)] for i, v in enumerate(latin))
        outer_hex = encoded.decode("ascii")
    except UnicodeError as exc:
        raise UnsupportedFormat("Encoding lapisan luar tidak cocok dengan profil legacy a/b") from exc
    verified = []

    def opened(value: str, key: bytes, label: str) -> str:
        text = open_record(value, key, profile.nonce, label)
        verified.append(label)
        return text

    envelope = _object(opened(outer_hex, profile.outer_key, "outer"), "outer")
    config = envelope.get("a")
    if not isinstance(config, dict) or not isinstance(envelope.get("b"), str):
        raise UnsupportedFormat("Pembungkus bukan format a/b yang didukung")
    if set(envelope) != {"a", "b"}:
        raise UnsupportedFormat("Pembungkus memiliki bagian tambahan; diperlukan profil baru")
    delimiter = config.get("uv")
    if not isinstance(delimiter, str) or not delimiter or not isinstance(config.get("xy"), str):
        raise UnsupportedFormat("Konfigurasi a.xy atau delimiter a.uv tidak ditemukan")
    metadata = {}
    for key, value in config.items():
        if key != "xy":
            metadata[key] = opened(value, profile.field_key, "metadata." + key)
    metadata["root_b"] = opened(envelope["b"], profile.field_key, "metadata.root_b")
    joined = opened(config["xy"], profile.main_key, "main_configuration")
    # The separator is the encrypted uv value, NOT the decrypted metadata value.
    tokens = joined.split(delimiter)
    if len(tokens) != profile.field_count:
        raise UnsupportedFormat(f"Jumlah kolom {len(tokens)}; profil mengharapkan {profile.field_count}")
    fields = []
    for index, token in enumerate(tokens):
        methods = []
        is_hex = len(token) >= 32 and len(token) % 2 == 0 and re.fullmatch(r"[0-9a-fA-F]+", token)
        if index == 24 and len(token) == 120 and is_hex:
            value = "".join(opened(token[n:n+60], profile.field_key, f"field24.part{n//60}") for n in (0, 60))
            methods.append("two_authenticated_records")
        elif is_hex:
            value = opened(token, profile.field_key, f"field{index}")
            methods.append("authenticated_record")
        else:
            value = token
        value, changed = decode_jkl(value, profile.jkl_xor)
        if changed:
            methods.append("jkl_decoded")
        if index in (7, 11):
            value, changed = decode_credentials(value, index == 7)
            if changed:
                methods.append("credential_representation_decoded")
        fields.append({"index": index, "label": LABELS.get(index, f"field_{index:02d}_unmapped"),
                       "value": value, "decoding": methods or ["within_authenticated_main"]})
    values = [f["value"] for f in fields]
    connection = {"name": values[18], "expiry_raw": values[4], "payload": values[0],
                  "remote_proxy": values[1], "tls_sni_raw": values[12]}
    if values[7]:
        match = re.fullmatch(r"(.+):(\d+)@([^:]+):(.+)", values[7])
        if not match or not 1 <= int(match[2]) <= 65535:
            raise DecodeError("field7: kredensial SSH tidak dapat diinterpretasikan oleh profil ini")
        connection["ssh"] = {"host": match[1], "port": int(match[2]),
                             "username": match[3], "password": match[4]}
    if values[25] not in {"true", "false"}:
        raise UnsupportedFormat("field25: flag V2Ray tidak dikenali")
    if values[26]:
        v2ray = _object(values[26], "field26.v2ray")
        if not isinstance(v2ray.get("outbounds"), list) or not v2ray["outbounds"]:
            raise DecodeError("field26.v2ray: outbounds kosong atau tidak valid")
        connection["v2ray"] = v2ray
    if values[25] == "true" and "v2ray" not in connection:
        raise DecodeError("V2Ray diaktifkan tetapi konfigurasi JSON kosong")
    return {
        "schema_version": 1, "source": source, "source_sha256": hashlib.sha256(raw).hexdigest(),
        "profile": profile.name, "connection": connection, "fields": fields, "metadata": metadata,
        "validation": {"field_count": len(fields), "authenticated_records": len(verified),
                       "all_checked_mac_valid": True, "verified_labels": verified,
                       "server_connection_tested": False},
    }


def decode_file(path: str | Path, *, profile: Profile = LEGACY_AB) -> dict:
    path = Path(path)
    # Bounded read also covers a file growing after stat, without allocating unbounded memory.
    with path.open("rb") as stream:
        raw = stream.read(profile.max_input_bytes + 1)
    return decode_bytes(raw, source=path.name, profile=profile)
