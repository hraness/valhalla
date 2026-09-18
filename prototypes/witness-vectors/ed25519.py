#!/usr/bin/env python3
"""Pure-Python Ed25519 in the RFC 8032 reference style.

Only `hashlib` is imported, so a verifier built on this module shares no code,
no library, and no arithmetic with the `ed25519-dalek` implementation the crate
signs with. It is a checker for committed vectors, not a production signer: it
is not constant time and it holds no secret. `verify` implements the RFC 8032
cofactored verification equation [8][S]B = [8]R + [8][k]A written as the plain
[S]B = R + [k]A check the reference code uses, and additionally rejects a
non-canonical S, which is what makes a signature one value rather than many.
"""

import hashlib

# The curve25519 field prime and the group order.
P = 2**255 - 19
Q = 2**252 + 27742317777372353535851937790883648493


def _sha512(data):
    return hashlib.sha512(data).digest()


def _inv(x):
    return pow(x, P - 2, P)


D = -121665 * _inv(121666) % P
SQRT_M1 = pow(2, (P - 1) // 4, P)


def _recover_x(y, sign):
    """The x with the given low bit for a y on the curve, or None."""
    if y >= P:
        return None
    x2 = (y * y - 1) * _inv(D * y * y + 1) % P
    if x2 == 0:
        return None if sign else 0
    x = pow(x2, (P + 3) // 8, P)
    if (x * x - x2) % P != 0:
        x = x * SQRT_M1 % P
    if (x * x - x2) % P != 0:
        return None
    if (x & 1) != sign:
        x = P - x
    return x


_G_Y = 4 * _inv(5) % P
_G_X = _recover_x(_G_Y, 0)
# Extended homogeneous coordinates (X, Y, Z, T) with x = X/Z, y = Y/Z, xy = T/Z.
G = (_G_X, _G_Y, 1, _G_X * _G_Y % P)
IDENTITY = (0, 1, 1, 0)


def _add(p, q):
    a = (p[1] - p[0]) * (q[1] - q[0]) % P
    b = (p[1] + p[0]) * (q[1] + q[0]) % P
    c = 2 * p[3] * q[3] * D % P
    d = 2 * p[2] * q[2] % P
    e, f, g, h = b - a, d - c, d + c, b + a
    return (e * f % P, g * h % P, f * g % P, e * h % P)


def _mul(scalar, point):
    out = IDENTITY
    while scalar > 0:
        if scalar & 1:
            out = _add(out, point)
        point = _add(point, point)
        scalar >>= 1
    return out


def _equal(p, q):
    if (p[0] * q[2] - q[0] * p[2]) % P != 0:
        return False
    return (p[1] * q[2] - q[1] * p[2]) % P == 0


def decompress(data):
    """A point from its 32-byte little-endian encoding, or None."""
    if len(data) != 32:
        return None
    y = int.from_bytes(data, "little")
    sign = y >> 255
    y &= (1 << 255) - 1
    x = _recover_x(y, sign)
    if x is None:
        return None
    return (x, y, 1, x * y % P)


def compress(point):
    """The 32-byte little-endian encoding of a point."""
    zinv = _inv(point[2])
    x = point[0] * zinv % P
    y = point[1] * zinv % P
    return int.to_bytes(y | ((x & 1) << 255), 32, "little")


def is_small_order(point):
    """Whether the point lies in the order-8 torsion subgroup."""
    return _equal(_mul(8, point), IDENTITY)


def verify(public, message, signature):
    """Whether `signature` is a valid Ed25519 signature of `message`."""
    if len(public) != 32 or len(signature) != 64:
        return False
    a = decompress(public)
    if a is None or is_small_order(a):
        return False
    r = decompress(signature[:32])
    if r is None:
        return False
    s = int.from_bytes(signature[32:], "little")
    if s >= Q:
        return False
    k = int.from_bytes(_sha512(signature[:32] + public + message), "little") % Q
    return _equal(_mul(s, G), _add(r, _mul(k, a)))


def self_test():
    """RFC 8032 section 7.1 test vector 2: one signature and three refusals."""
    public = bytes.fromhex(
        "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c"
    )
    message = bytes.fromhex("72")
    signature = bytes.fromhex(
        "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da"
        "085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00"
    )
    assert verify(public, message, signature), "the RFC vector must verify"
    assert not verify(public, b"\x73", signature), "a changed message must fail"
    assert not verify(public, message, signature[:63] + b"\x01"), "a changed S must fail"
    assert not verify(bytes(32), message, signature), "a small-order key must fail"


if __name__ == "__main__":
    self_test()
    print("ed25519: RFC 8032 vector 2 verifies and three forgeries are refused")
