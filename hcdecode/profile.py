"""Constants for the observed a/b format. These are app format keys, not accounts."""
from dataclasses import dataclass


@dataclass(frozen=True)
class Profile:
    name: str
    outer_xor: bytes
    outer_key: bytes
    main_key: bytes
    field_key: bytes
    nonce: bytes
    jkl_xor: bytes
    field_count: int = 32
    max_input_bytes: int = 16 * 1024 * 1024


LEGACY_AB = Profile(
    name="legacy-ab-original-chacha64",
    outer_xor=bytes.fromhex("e382e4b8adc386f09f9293"),
    outer_key=bytes.fromhex("81342f558a6273bac4548d473f54c4ffc7c41747dee81369acab9c787d41ab9c"),
    main_key=bytes.fromhex("3380aa278b744ba5b529a7f32fa803e48749280dae378345d9b526cf1dbce372"),
    field_key=bytes.fromhex("3d632a251c9820f2baf83e15498d27548fc67921cb437f8ce48505989378adea"),
    nonce=b"\xdb" * 8,
    jkl_xor=bytes.fromhex("d5d4d3d2d1d0cfcecdccbdbcbbbab9b8b7b6b5b4"),
)
