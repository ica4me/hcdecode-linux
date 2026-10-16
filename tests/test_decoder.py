import contextlib
from dataclasses import replace
import io
import json
from pathlib import Path
import stat
import tempfile
import unittest

from hcdecode import DecodeError, decode_bytes, decode_file
from hcdecode.cli import main, write_private
from hcdecode.crypto import open_record
from hcdecode.errors import AuthenticationError, UnsupportedFormat
from hcdecode.profile import LEGACY_AB
from hcdecode.reporting import render

ROOT = Path(__file__).resolve().parents[1]
SSH = ROOT / "examples/demo_ssh.hc"
TROJAN = ROOT / "examples/demo_trojan.hc"
FIXTURES = ROOT / "tests/fixtures"


class DecoderTests(unittest.TestCase):
    def test_independent_libsodium_vector(self):
        vector = json.loads((FIXTURES / "original_chacha_vector.json").read_text())
        plain = open_record(vector["record_hex"], bytes.fromhex(vector["key_hex"]),
                            bytes.fromhex(vector["nonce_hex"]), "vector")
        self.assertEqual(plain, vector["plaintext"])

    def test_vector_tag_tampering(self):
        v = json.loads((FIXTURES / "original_chacha_vector.json").read_text())
        record = bytearray.fromhex(v["record_hex"])
        record[-1] ^= 1
        with self.assertRaises(AuthenticationError):
            open_record(record.hex(), bytes.fromhex(v["key_hex"]), bytes.fromhex(v["nonce_hex"]), "vector")

    def test_ssh_braille_arithmetic_and_long_notes(self):
        result = decode_file(SSH)
        self.assertEqual(result["connection"]["ssh"]["username"], "demo_user")
        self.assertEqual(result["connection"]["ssh"]["password"], "DemoOnly123!")
        self.assertEqual(result["validation"]["field_count"], 32)
        self.assertGreater(len(result["fields"][6]["value"]), 20000)
        self.assertEqual(result["connection"]["tls_sni_raw"], "vpn.example.com")
        self.assertEqual(result["fields"][24]["value"], "[splitPsiphon][splitPsiphon]")

    def test_v2ray_json_and_empty_records(self):
        result = decode_file(TROJAN)
        self.assertEqual(result["connection"]["payload"], "")
        out = result["connection"]["v2ray"]["outbounds"][0]
        self.assertEqual(out["protocol"], "trojan")
        self.assertEqual(out["settings"]["servers"][0]["port"], 443)

    def test_default_redaction_does_not_mutate_plaintext(self):
        for path, secret in [(SSH, "DemoOnly123!"), (TROJAN, "ExampleTrojanPasswordOnly")]:
            with self.subTest(path=path.name):
                decoded = decode_file(path)
                rendered = render(decoded)
                text = json.dumps(rendered)
                self.assertNotIn(secret, text)
                self.assertNotIn("620000000000", text)
                self.assertIn(secret, json.dumps(decoded))
                self.assertEqual(rendered["fields"][6]["value"], "[NOTES OMITTED]")

    def test_show_secrets_retains_raw_v2ray(self):
        decoded = decode_file(TROJAN)
        actual = render(decoded, show_secrets=True, v2ray_only=True)
        self.assertEqual(actual, json.loads(decoded["fields"][26]["value"]))

    def test_authenticated_outer_does_not_hide_invalid_field(self):
        with self.assertRaisesRegex(AuthenticationError, "field7:"):
            decode_file(FIXTURES / "bad_field.hc")

    def test_outer_tampering(self):
        key = LEGACY_AB.outer_xor
        def xor(data):
            return bytes(v ^ key[i % len(key)] for i, v in enumerate(data))
        outer = bytearray(xor(SSH.read_bytes().decode("utf-8").encode("latin1")))
        outer[0] = ord("0") if outer[0] != ord("0") else ord("1")
        corrupt = xor(outer).decode("latin1").encode("utf-8")
        with self.assertRaisesRegex(AuthenticationError, "outer:"):
            decode_bytes(corrupt)

    def test_unknown_field_layout_is_rejected(self):
        with self.assertRaises(UnsupportedFormat):
            decode_file(FIXTURES / "wrong_field_count.hc")

    def test_empty_invalid_and_oversize_inputs(self):
        for data in (b"", b"not a hc file", b"\xff\xfe"):
            with self.subTest(data=data), self.assertRaises(DecodeError):
                decode_bytes(data)
        with self.assertRaises(DecodeError):
            decode_bytes(b"x" * 21, profile=replace(LEGACY_AB, max_input_bytes=20))

    def test_ssh_has_no_v2ray_export(self):
        with self.assertRaisesRegex(DecodeError, "tidak memiliki JSON V2Ray"):
            render(decode_file(SSH), v2ray_only=True)

    def test_cli_private_output_and_no_overwrite(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "result.json"
            with contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(main(["decode", str(TROJAN), "-o", str(target)]), 0)
                before = target.read_bytes()
                self.assertEqual(main(["decode", str(SSH), "-o", str(target)]), 1)
            self.assertEqual(before, target.read_bytes())
            self.assertEqual(stat.S_IMODE(target.stat().st_mode), 0o600)
            self.assertTrue(json.loads(before)["redacted"])

    def test_output_symlink_is_not_followed(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "real"
            target.write_text("keep")
            link = Path(tmp) / "link"
            link.symlink_to(target)
            with self.assertRaises(FileExistsError):
                write_private(link, "replace")
            self.assertEqual(target.read_text(), "keep")

    def test_batch_continues_and_returns_failure(self):
        with tempfile.TemporaryDirectory() as tmp:
            errors = io.StringIO()
            with contextlib.redirect_stderr(errors):
                status = main(["decode", str(FIXTURES / "bad_field.hc"), str(TROJAN), "--out-dir", tmp])
            self.assertEqual(status, 1)
            self.assertTrue((Path(tmp) / "demo_trojan.decoded.json").exists())
            self.assertFalse((Path(tmp) / "bad_field.decoded.json").exists())
            self.assertNotIn("ExampleTrojanPasswordOnly", errors.getvalue())


if __name__ == "__main__":
    unittest.main()
