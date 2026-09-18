#!/usr/bin/env python3
"""Re-derives every digest in vectors/witness-v1.json from its hex fields."""
import hashlib
import json
import struct
from pathlib import Path

path = Path(__file__).resolve().parents[2] / "vectors" / "witness-v1.json"
v = json.loads(path.read_text())
assert v["version"] == 1


def digest(domain, body):
    return hashlib.sha256(domain + struct.pack(">I", len(body)) + body).hexdigest()


program = bytes.fromhex(v["program_hex"])
candidate = bytes.fromhex(v["candidate_hex"])
manifest = bytes.fromhex(v["manifest_hex"])
receipt = bytes.fromhex(v["receipt_hex"])
body = bytes.fromhex(v["challenge_body_hex"])
assert program[:2] == b"\x01\x01" and candidate[:3] == b"\x01\x01\x01" and manifest[:2] == b"\x01\x01"
assert candidate[5:] == program[2:], "the candidate carries the program body after its cell id"
assert len(receipt) == 180 and len(body) == 196
assert digest(b"vhalla/witness/assignment/v1", candidate) == v["program_hash_hex"]
assert digest(b"vhalla/witness/manifest/v1", manifest) == v["manifest_hash_hex"]
assert digest(b"vhalla/witness/receipt/v1", receipt) == v["receipt_hash_hex"]
transcript = b"vhalla/botcaptcha/challenge/v1" + struct.pack(">I", len(body)) + body
assert transcript.hex() == v["challenge_transcript_hex"]
scope = body[34:66] + body[2:34] + body[66:98]
assert digest(b"vhalla/botcaptcha/dedup/v1", scope) == v["dedup_key_hex"]
assert int.from_bytes(manifest[-25:-17], "big") == v["manifest_loading_work"] == len(manifest)
challenge_hash = bytes.fromhex(digest(b"vhalla/botcaptcha/challenge/v1", body))
work = bytes.fromhex(digest(b"vhalla/botcaptcha/pow/v1", challenge_hash + body[66:98] + struct.pack(">Q", 12345)))
assert work.hex() == v["hashcash_work_digest_hex"]
leading = 0
for byte in work:
    if byte == 0:
        leading += 8
    else:
        leading += 8 - byte.bit_length()
        break
assert leading == v["hashcash_leading_zero_bits"]
print(f"witness-v1: program {len(program)} bytes, manifest {len(manifest)} bytes, receipt {len(receipt)} bytes, all digests re-derived")
