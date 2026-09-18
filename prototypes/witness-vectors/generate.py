#!/usr/bin/env python3
"""Independent Python struct/hashlib oracle for the witness-v1 encodings.

Writes vectors/witness-v1.json at the repository root from a hand-authored
program, candidate, manifest, claimed receipt, and challenge transcript. It
shares no code with the Rust crates; the Rust tests assert these hex strings
verbatim, and verify-vectors.py re-derives every digest from the hex.
"""
import hashlib
import json
import struct
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
OUT = ROOT / "vectors" / "witness-v1.json"

VERSION = 1
LANGUAGE = 1
DIRECTION = {"north": 1, "east": 2, "south": 3, "west": 4}
RELATIVE = {"forward": 1, "left": 2, "right": 3, "back": 4}


def digest(domain: bytes, body: bytes) -> bytes:
    return hashlib.sha256(domain + struct.pack(">I", len(body)) + body).digest()


def u8(v): return struct.pack(">B", v)
def u16(v): return struct.pack(">H", v)
def u32(v): return struct.pack(">I", v)
def u64(v): return struct.pack(">Q", v)
def u128(v): return v.to_bytes(16, "big")
def boolean(v): return u8(1 if v else 0)


def condition(c):
    kind = c["kind"]
    if kind in ("carrying", "at_source", "at_depot", "at_beacon", "at_receiver"):
        tag = {"carrying": 1, "at_source": 2, "at_depot": 3, "at_beacon": 4, "at_receiver": 5}[kind]
        return u8(tag) + boolean(c["value"])
    if kind == "blocked":
        return u8(6) + u8(RELATIVE[c["direction"]]) + boolean(c["value"])
    if kind == "has_message":
        return u8(7) + u8(c["port"]) + boolean(c["value"])
    if kind == "message_bit":
        return u8(8) + u8(c["port"]) + boolean(c["value"])
    if kind == "memory":
        return u8(9) + u8(c["slot"]) + u8(c["value"])
    if kind == "heading":
        return u8(10) + u8(DIRECTION[c["direction"]])
    raise ValueError(kind)


def bit_source(b):
    kind = b["kind"]
    if kind == "constant":
        return u8(1) + boolean(b["value"])
    if kind == "memory":
        return u8(2) + u8(b["slot"])
    if kind == "message":
        return u8(3) + u8(b["port"])
    raise ValueError(kind)


def action(a):
    kind = a["kind"]
    if kind == "move":
        return u8(1) + u8(RELATIVE[a["direction"]])
    if kind == "turn":
        return u8(2) + u8(RELATIVE[a["direction"]])
    if kind == "pickup":
        return u8(3)
    if kind == "drop":
        return u8(4)
    if kind == "wait":
        return u8(5)
    if kind == "write_memory":
        return u8(6) + u8(a["slot"]) + u8(a["value"])
    if kind == "take_message":
        return u8(7) + u8(a["port"]) + u8(a["slot"])
    if kind == "send":
        return u8(8) + u8(a["port"]) + bit_source(a["bit"])
    if kind == "route":
        return u8(9) + u16(a["valve"]) + bit_source(a["bit"])
    raise ValueError(kind)


def program_body(rules):
    out = u8(len(rules))
    for rule in rules:
        out += u8(len(rule["when"]))
        for c in rule["when"]:
            out += condition(c)
        out += action(rule["action"])
        remember = rule.get("remember")
        if remember is None:
            out += u8(0)
        else:
            out += u8(1) + u8(remember["slot"]) + u8(remember["value"])
    return out


def header():
    return u8(VERSION) + u8(LANGUAGE)


def point(p):
    return u8(p[0]) + u8(p[1])


def world(w):
    out = u8(w["width"]) + u8(w["height"])
    out += u16(len(w["walls"]))
    for p in w["walls"]:
        out += point(p)
    out += u8(len(w["sources"]))
    for s in w["sources"]:
        out += u16(s["id"]) + point(s["position"]) + u8(len(s["sparks"]))
        for spark in s["sparks"]:
            out += u32(spark["id"]) + boolean(spark["bit"])
    out += u8(len(w["depots"]))
    for d in w["depots"]:
        out += u16(d["id"]) + point(d["position"]) + u8(d["capacity"])
    out += u8(len(w["beacons"]))
    for b in w["beacons"]:
        out += u16(b["id"]) + point(b["position"]) + boolean(b["accepts"])
        out += u32(b["initial_charge"]) + u32(b["drain_every"]) + u32(b["drain_amount"])
        out += u32(b["spark_charge"]) + u32(b["required_deliveries"])
    out += u8(len(w["valves"]))
    for v in w["valves"]:
        out += u16(v["id"]) + point(v["position"]) + u16(v["depot"])
        out += u16(v["beacon_zero"]) + u16(v["beacon_one"]) + boolean(v["enabled"])
    out += u8(len(w["cells"]))
    for c in w["cells"]:
        out += u16(c["id"]) + point(c["position"]) + u8(DIRECTION[c["heading"]])
        out += boolean(c["mobile"]) + bytes(c["memory"])
    out += u8(len(w["links"]))
    for l in w["links"]:
        out += u16(l["id"])
        f = l["from"]
        if f["kind"] == "cell":
            out += u8(1) + u16(f["id"]) + u8(f["port"])
        else:
            out += u8(2) + u16(f["id"])
        out += u16(l["to_cell"]) + u8(l["to_port"]) + u32(l["delay"]) + boolean(l["enabled"])
    return out


def case(c, loading_work):
    out = u64(c["seed"]) + u32(c["ticks"]) + u64(c["fuel"]) + u32(c["activation_fuel"])
    out += u8(len(c["events"]))
    for e in c["events"]:
        out += u32(e["tick"])
        kind = e["kind"]
        if kind == "link_enabled":
            out += u8(1) + u16(e["id"]) + boolean(e["enabled"])
        elif kind == "valve_enabled":
            out += u8(2) + u16(e["id"]) + boolean(e["enabled"])
        else:
            out += u8(3) + u16(e["cell"])
    out += u64(loading_work)
    return out


def manifest(m, loading_work):
    out = header() + world(m["world"])
    out += u8(len(m["slots"]))
    for slot in m["slots"]:
        out += u16(slot["cell"])
        if slot.get("fixed") is None:
            out += u8(0)
        else:
            out += u8(1) + program_body(slot["fixed"])
    out += u8(len(m["cases"]))
    for c in m["cases"]:
        out += case(c, loading_work)
    contract = m["contract"]
    out += u64(contract["useful_floor"]) + u64(contract["total_ceiling"]) + boolean(contract["require_passed"])
    return out


PROGRAM = [
    {"when": [{"kind": "carrying", "value": False}, {"kind": "at_source", "value": True}],
     "action": {"kind": "pickup"}},
    {"when": [{"kind": "carrying", "value": True}, {"kind": "at_beacon", "value": True}],
     "action": {"kind": "drop"}, "remember": {"slot": 0, "value": 1}},
    {"when": [{"kind": "blocked", "direction": "forward", "value": False}],
     "action": {"kind": "move", "direction": "forward"}},
    {"when": [], "action": {"kind": "turn", "direction": "left"}},
]

MANIFEST = {
    "world": {
        "width": 5, "height": 3, "walls": [[2, 0], [2, 2]],
        "sources": [{"id": 10, "position": [0, 1], "sparks": [{"id": 1, "bit": True}, {"id": 2, "bit": False}]}],
        "depots": [],
        "beacons": [{"id": 20, "position": [4, 1], "accepts": True, "initial_charge": 10,
                     "drain_every": 8, "drain_amount": 1, "spark_charge": 4, "required_deliveries": 1}],
        "valves": [],
        "cells": [{"id": 1, "position": [0, 1], "heading": "east", "mobile": True, "memory": [0, 0, 0, 0]}],
        "links": [],
    },
    "slots": [{"cell": 1}],
    "cases": [{"seed": 7, "ticks": 16, "fuel": 4000, "activation_fuel": 64, "events": []}],
    "contract": {"useful_floor": 1, "total_ceiling": 4000, "require_passed": False},
}

RECEIPT = {
    "challenge_id": bytes(range(32)),
    "subject_key": bytes([9] * 32),
    "manifest": bytes([1] * 32),
    "program": bytes([2] * 32),
    "output": bytes([3] * 32),
    "useful": 5,
    "total": 123456789,
    "passed": True,
    "case_count": 1,
}

CHALLENGE = {
    "challenge_id": bytes(range(32)),
    "issuer_key": bytes([7] * 32),
    "subject_key": bytes([9] * 32),
    "realm": 1,
    "room": 2,
    "purpose": 1,
    "manifest": bytes([1] * 32),
    "issued_at": 1_000_000,
    "expires_at": 1_000_600,
    "useful_floor": 1,
    "total_ceiling": 4000,
    "require_passed": False,
}


def main():
    program = header() + program_body(PROGRAM)
    candidate = header() + u8(1) + u16(1) + program_body(PROGRAM)
    # loading_work is inside the manifest but fixed width, so the length is stable.
    length = len(manifest(MANIFEST, 0))
    manifest_bytes = manifest(MANIFEST, length)
    assert len(manifest_bytes) == length
    receipt = header() + RECEIPT["challenge_id"] + RECEIPT["subject_key"] + RECEIPT["manifest"]
    receipt += RECEIPT["program"] + RECEIPT["output"] + u64(RECEIPT["useful"]) + u64(RECEIPT["total"])
    receipt += boolean(RECEIPT["passed"]) + u8(RECEIPT["case_count"])
    challenge_body = u8(VERSION) + u8(2) + CHALLENGE["challenge_id"] + CHALLENGE["issuer_key"]
    challenge_body += CHALLENGE["subject_key"] + u128(CHALLENGE["realm"]) + u128(CHALLENGE["room"])
    challenge_body += u8(CHALLENGE["purpose"]) + CHALLENGE["manifest"] + u64(CHALLENGE["issued_at"])
    challenge_body += u64(CHALLENGE["expires_at"]) + u64(CHALLENGE["useful_floor"])
    challenge_body += u64(CHALLENGE["total_ceiling"]) + boolean(CHALLENGE["require_passed"])
    challenge_domain = b"vhalla/botcaptcha/challenge/v1"
    scope = CHALLENGE["issuer_key"] + CHALLENGE["challenge_id"] + CHALLENGE["subject_key"]
    challenge_hash = digest(challenge_domain, challenge_body)
    work = digest(b"vhalla/botcaptcha/pow/v1", challenge_hash + CHALLENGE["subject_key"] + u64(12345))
    leading = 0
    for byte in work:
        if byte == 0:
            leading += 8
        else:
            leading += 8 - byte.bit_length()
            break
    out = {
        "version": 1,
        "source": "Independent Python struct/hashlib encodings of hand-authored witness values; fixed public bytes, never identities for deployment.",
        "program_hex": program.hex(),
        "candidate_hex": candidate.hex(),
        "program_hash_hex": digest(b"vhalla/witness/assignment/v1", candidate).hex(),
        "manifest_hex": manifest_bytes.hex(),
        "manifest_loading_work": length,
        "manifest_hash_hex": digest(b"vhalla/witness/manifest/v1", manifest_bytes).hex(),
        "receipt_hex": receipt.hex(),
        "receipt_hash_hex": digest(b"vhalla/witness/receipt/v1", receipt).hex(),
        "challenge_body_hex": challenge_body.hex(),
        "challenge_transcript_hex": (challenge_domain + u32(len(challenge_body)) + challenge_body).hex(),
        "dedup_key_hex": digest(b"vhalla/botcaptcha/dedup/v1", scope).hex(),
        "hashcash_work_digest_hex": work.hex(),
        "hashcash_leading_zero_bits": leading,
    }
    OUT.write_text(json.dumps(out, indent=2) + "\n")
    print(f"wrote {OUT.relative_to(ROOT)}: program {len(program)} bytes, manifest {length} bytes")


if __name__ == "__main__":
    main()
