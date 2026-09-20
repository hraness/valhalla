"""Reproduce PUBLIC author-page fixture using installed libsodium, not Rust."""

import ctypes as c
import sys

if len(sys.argv) != 2:
    raise SystemExit("usage: generate_author_page.py /absolute/path/to/libsodium")
sodium = c.CDLL(sys.argv[1])
sodium.sodium_init.restype = c.c_int
assert sodium.sodium_init() >= 0
sodium.crypto_sign_seed_keypair.argtypes = [c.c_void_p, c.c_void_p, c.c_void_p]
sodium.crypto_sign_seed_keypair.restype = c.c_int
sodium.crypto_kdf_hkdf_sha256_extract.argtypes = [
    c.c_void_p, c.c_void_p, c.c_size_t, c.c_void_p, c.c_size_t,
]
sodium.crypto_kdf_hkdf_sha256_extract.restype = c.c_int
sodium.crypto_kdf_hkdf_sha256_expand.argtypes = [
    c.c_void_p, c.c_size_t, c.c_void_p, c.c_size_t, c.c_void_p,
]
sodium.crypto_kdf_hkdf_sha256_expand.restype = c.c_int
sodium.crypto_aead_xchacha20poly1305_ietf_encrypt.argtypes = [
    c.c_void_p, c.c_void_p, c.c_void_p, c.c_ulonglong, c.c_void_p,
    c.c_ulonglong, c.c_void_p, c.c_void_p, c.c_void_p,
]
sodium.crypto_aead_xchacha20poly1305_ietf_encrypt.restype = c.c_int

seed = bytes([7] * 32)
backup = bytes([3] * 32)
nonce = bytes([4] * 24)
public = c.create_string_buffer(32)
secret = c.create_string_buffer(64)
assert sodium.crypto_sign_seed_keypair(public, secret, seed) == 0
scope = bytes([2] * 112) + public.raw + bytes([2] * 32)
info = b"vhalla/author-state/backup/key/v1" + scope
prk = c.create_string_buffer(32)
key = c.create_string_buffer(32)
assert sodium.crypto_kdf_hkdf_sha256_extract(prk, backup, len(backup), seed, len(seed)) == 0
assert sodium.crypto_kdf_hkdf_sha256_expand(key, 32, info, len(info), prk) == 0
payload = b"bounded signed author state"
header = (b"VHBENC01" + scope + backup + (0).to_bytes(8, "big") + bytes(32)
          + b"\x00" + nonce + len(payload).to_bytes(4, "big"))
assert len(header) == 285
output = c.create_string_buffer(len(payload) + 16)
size = c.c_ulonglong()
assert sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(
    output, c.byref(size), payload, len(payload), header, len(header), None, nonce, key,
) == 0
assert size.value == len(payload) + 16
print((header + output.raw).hex())
