"""Command-line entry point; no network, subprocess, APK execution, or memory hooks."""
import argparse
import json
import os
from pathlib import Path
import sys

from . import __version__
from .decoder import decode_file
from .errors import DecodeError
from .profile import LEGACY_AB
from .reporting import render


def write_private(path: Path, text: str) -> None:
    """Exclusive creation avoids replacing inputs, existing reports, and symlinks."""
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            stream.write(text)
    except BaseException:
        path.unlink(missing_ok=True)
        raise


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="hcdecode", description="Decoder HC offline untuk profil legacy a/b yang telah diuji")
    parser.add_argument("--version", action="version", version=__version__)
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("profiles", help="Tampilkan profil dan batas dukungan")
    decode = commands.add_parser("decode", help="Dekripsi dan verifikasi satu atau beberapa HC")
    decode.add_argument("files", type=Path, nargs="+")
    destination = decode.add_mutually_exclusive_group()
    destination.add_argument("-o", "--output", type=Path, help="File JSON untuk satu input; tidak menimpa file lama")
    destination.add_argument("--out-dir", type=Path, help="Folder hasil untuk pemrosesan batch")
    decode.add_argument("--show-secrets", action="store_true", help="Sertakan kredensial dan catatan asli dalam keluaran lokal")
    decode.add_argument("--v2ray-only", action="store_true", help="Ekspor objek JSON V2Ray saja")
    args = parser.parse_args(argv)
    if args.command == "profiles":
        print(json.dumps({"profile": LEGACY_AB.name, "fields": 32,
                          "observed_config_build": "645", "max_input_bytes": LEGACY_AB.max_input_bytes,
                          "unsupported": ["HCCFG modern", "cfg/content", "nonce turunan password/HWID", "live Android memory sniff"]}, indent=2))
        return 0
    if len(args.files) > 1 and args.out_dir is None:
        parser.error("Beberapa input memerlukan --out-dir")
    if args.out_dir is not None:
        try:
            args.out_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        except OSError as exc:
            print(f"ERROR: {exc}", file=sys.stderr)
            return 1
    failures = 0
    for source in args.files:
        try:
            decoded = decode_file(source)
            result = render(decoded, show_secrets=args.show_secrets, v2ray_only=args.v2ray_only)
            text = json.dumps(result, ensure_ascii=False, indent=2) + "\n"
            output = args.output
            if args.out_dir is not None:
                suffix = ".v2ray.json" if args.v2ray_only else ".decoded.json"
                output = args.out_dir / (source.stem + suffix)
            if output is None:
                print(text, end="")
            else:
                write_private(output, text)
                v = decoded["validation"]
                print(f"OK: {source.name}: {v['field_count']} fields, {v['authenticated_records']} MAC valid -> {output}", file=sys.stderr)
        except (DecodeError, OSError, RecursionError) as exc:
            failures += 1
            print(f"ERROR: {source.name}: {exc}", file=sys.stderr)
    return 1 if failures else 0
