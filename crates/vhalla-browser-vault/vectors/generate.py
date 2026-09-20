"""Reproduce PUBLIC test vectors using an installed libsodium, never real keys."""

import ctypes as c
import sys

if len(sys.argv) != 2:
    raise SystemExit("usage: generate.py /absolute/path/to/libsodium")

sodium = c.CDLL(sys.argv[1])
sodium.sodium_init.restype = c.c_int
if sodium.sodium_init() < 0:
    raise SystemExit("libsodium initialization failed")
sodium.sodium_version_string.restype = c.c_char_p
sodium.crypto_pwhash.argtypes = [
    c.c_void_p,
    c.c_ulonglong,
    c.c_void_p,
    c.c_ulonglong,
    c.c_void_p,
    c.c_ulonglong,
    c.c_size_t,
    c.c_int,
]
sodium.crypto_pwhash.restype = c.c_int
sodium.crypto_pwhash_alg_argon2id13.restype = c.c_int
sodium.crypto_sign_seed_keypair.argtypes = [c.c_void_p, c.c_void_p, c.c_void_p]
sodium.crypto_sign_seed_keypair.restype = c.c_int
sodium.crypto_aead_xchacha20poly1305_ietf_encrypt.argtypes = [
    c.c_void_p,
    c.c_void_p,
    c.c_void_p,
    c.c_ulonglong,
    c.c_void_p,
    c.c_ulonglong,
    c.c_void_p,
    c.c_void_p,
    c.c_void_p,
]
sodium.crypto_aead_xchacha20poly1305_ietf_encrypt.restype = c.c_int

seed = bytes(range(32))
salt = bytes(range(32, 48))
nonce = bytes(range(48, 72))
password = b"Valhalla public fixture password v1"
public = c.create_string_buffer(32)
secret = c.create_string_buffer(64)
assert sodium.crypto_sign_seed_keypair(public, secret, seed) == 0
other_public = c.create_string_buffer(32)
assert sodium.crypto_sign_seed_keypair(other_public, secret, bytes([1] * 32)) == 0
key = c.create_string_buffer(32)
assert (
    sodium.crypto_pwhash(
        key, 32, password, len(password), salt, 2, 19 * 1024 * 1024,
        sodium.crypto_pwhash_alg_argon2id13(),
    )
    == 0
)
print("libsodium", sodium.sodium_version_string().decode())
for name, claimed_public in (
    ("v1-envelope.hex", public.raw),
    ("v1-wrong-public.hex", other_public.raw),
):
    header = b"VHBV\x01" + salt + nonce + claimed_public
    output = c.create_string_buffer(48)
    size = c.c_ulonglong()
    assert (
        sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(
            output, c.byref(size), seed, len(seed), header, len(header), None,
            nonce, key,
        )
        == 0
    )
    assert size.value == 48
    print(name, (header + output.raw).hex())
