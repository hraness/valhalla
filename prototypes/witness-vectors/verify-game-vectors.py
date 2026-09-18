#!/usr/bin/env python3
"""Independent oracle for the frozen v1 game session vectors.

Reads `crates/vhalla-game-platonik/tests/vectors/game-v1-session-*.txt`,
recomputes every digest from the committed hex with `hashlib`, rebuilds each
record's `vhalla/game/record/v1` transcript from the wire bytes, and verifies
every Ed25519 signature with the pure-Python RFC 8032 code beside this file.
No third-party module is imported and no signature is skipped. Exits non-zero
on the first mismatch it can name and on any mismatch at all.
"""

import hashlib
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import ed25519  # noqa: E402  (the committed pure-Python verifier beside this file)

ROOT = Path(__file__).resolve().parents[2]
VECTORS = ROOT / "crates" / "vhalla-game-platonik" / "tests" / "vectors"

MANIFEST_DOMAIN = b"vhalla/game/manifest/v1"
SESSION_DOMAIN = b"vhalla/game/session/v1"
EVENT_DOMAIN = b"vhalla/game/event/v1"
CHECKPOINT_DOMAIN = b"vhalla/game/checkpoint/v1"
RECORD_DOMAIN = b"vhalla/game/record/v1"
RECEIPT_DOMAIN = b"vhalla/witness/receipt/v1"

KIND_EVENT = 3
SEAL_DISCRIMINANT = 6
VERSION = 1

failures = []


def check(condition, message):
    if not condition:
        failures.append(message)
    return condition


def digest(domain, body):
    """SHA-256 over the domain, a u32 big-endian length, and the bytes."""
    return hashlib.sha256(domain + struct.pack(">I", len(body)) + body).digest()


def read(path):
    fields = {}
    for line in path.read_text().splitlines():
        if ": " not in line:
            continue
        key, value = line.split(": ", 1)
        if key in fields:
            raise SystemExit(f"{path.name}: duplicate key {key}")
        fields[key] = value
    return fields


def unhex(fields, key):
    return bytes.fromhex(fields[key])


def split_record(raw):
    """version, kind, session, signer, body, signature."""
    version, kind = raw[0], raw[1]
    session, signer = raw[2:34], raw[34:66]
    length = struct.unpack(">I", raw[66:70])[0]
    body = raw[70 : 70 + length]
    signature = raw[70 + length :]
    return version, kind, session, signer, body, signature


def verify_vector(path):
    fields = read(path)
    name = fields["id"]
    manifest = unhex(fields, "game_manifest")
    manifest_hash = unhex(fields, "game_manifest_hash")
    check(
        digest(MANIFEST_DOMAIN, manifest) == manifest_hash,
        f"{name}: game manifest hash",
    )
    opening = unhex(fields, "session_open")
    session_key = unhex(fields, "session_key")
    check(digest(SESSION_DOMAIN, opening) == session_key, f"{name}: session key")
    check(opening[0] == VERSION, f"{name}: session open version byte")
    check(
        opening[33:65] == manifest_hash,
        f"{name}: the opening names the manifest hash",
    )
    check(opening[100] == 1, f"{name}: authority is Host")
    host = opening[101:133]

    count = int(fields["record_count"])
    check(count > 0, f"{name}: no records")
    seals = 0
    for index in range(count):
        at = f"record[{index}]."
        raw = unhex(fields, at + "record")
        version, kind, session, signer, body, signature = split_record(raw)
        check(version == VERSION, f"{name}: record {index} version byte")
        check(
            kind == int(fields[at + "kind"]) == KIND_EVENT,
            f"{name}: record {index} kind",
        )
        check(session == session_key, f"{name}: record {index} session key")
        check(signer.hex() == fields[at + "signer"], f"{name}: record {index} signer")
        check(len(signature) == 64, f"{name}: record {index} signature length")
        # The event header repeats the session key and carries the author key,
        # so a record cannot be re-signed for another session or author.
        check(body[0] == VERSION, f"{name}: record {index} event version byte")
        check(body[1:33] == session_key, f"{name}: record {index} event session")
        check(body[41:73] == signer, f"{name}: record {index} event author")
        parents = body[81]
        check(parents == 0, f"{name}: record {index} parent count")
        event_digest = digest(EVENT_DOMAIN, body)
        check(
            event_digest.hex() == fields[at + "event_digest"],
            f"{name}: record {index} event digest",
        )
        # The transcript: domain, u32 length, kind byte, session key, digest.
        inner = bytes([kind]) + session_key + event_digest
        transcript = RECORD_DOMAIN + struct.pack(">I", len(inner)) + inner
        check(
            ed25519.verify(signer, transcript, signature),
            f"{name}: record {index} signature",
        )
        body_kind = body[82 + parents * 32]
        is_seal = at + "checkpoint" in fields
        check(
            is_seal == (body_kind == SEAL_DISCRIMINANT),
            f"{name}: record {index} seal fields match the body",
        )
        if not is_seal:
            continue
        seals += 1
        check(signer == host, f"{name}: record {index} is host signed")
        checkpoint = unhex(fields, at + "checkpoint")
        checkpoint_hash = unhex(fields, at + "checkpoint_hash")
        check(
            digest(CHECKPOINT_DOMAIN, checkpoint) == checkpoint_hash,
            f"{name}: record {index} checkpoint hash",
        )
        check(checkpoint[0] == VERSION, f"{name}: record {index} checkpoint version")
        check(
            checkpoint[1:33] == session_key,
            f"{name}: record {index} checkpoint session",
        )
        # A seal's last field is the hash of the checkpoint it commits, so the
        # signed event and the committed checkpoint are one object.
        check(
            body[-32:] == checkpoint_hash,
            f"{name}: record {index} seals its checkpoint hash",
        )

    check(seals > 0, f"{name}: no seal")
    receipt = unhex(fields, "receipt")
    check(len(receipt) == 180, f"{name}: receipt is 180 bytes")
    check(receipt[0] == VERSION, f"{name}: receipt version byte")
    check(receipt[2:34] == session_key, f"{name}: receipt challenge id")
    check(receipt[34:66] == host, f"{name}: receipt subject key")
    check(
        digest(RECEIPT_DOMAIN, receipt).hex() == fields["receipt_hash"],
        f"{name}: receipt hash",
    )
    print(
        f"{name}: {count} records, {seals} seal(s), "
        f"manifest {len(manifest)} bytes, opening {len(opening)} bytes, "
        "every digest re-derived and every signature verified"
    )


def main():
    ed25519.self_test()
    names = ["game-v1-session-replay.txt", "game-v1-session-live.txt"]
    for name in names:
        path = VECTORS / name
        if not path.is_file():
            failures.append(f"missing vector {path}")
            continue
        verify_vector(path)
    if failures:
        for failure in failures:
            print(f"FAIL {failure}", file=sys.stderr)
        raise SystemExit(1)


if __name__ == "__main__":
    main()
