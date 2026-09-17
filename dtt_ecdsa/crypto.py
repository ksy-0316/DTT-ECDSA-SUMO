"""Hash functions and hashed EC-ElGamal encryption (Section II-C of the paper).

EC-ElGamal is used by the TMC to ship the confidential session parameters:

    T0 = kappa * G
    T1 = (t || gamma)          XOR H(kappa * pkR)     -> RSU
    T2 = (t || gamma || theta) XOR H(kappa * pkTr)    -> Tracer

Decryption exploits ``sk * T0 = sk * (kappa * G) = kappa * pk``.
"""

from __future__ import annotations

import hashlib

from . import curve
from .curve import Q, point_to_bytes

T_BYTES = 4               # threshold value t
S_BYTES = curve.SCALAR_BYTES   # gamma, theta

T1_LEN = T_BYTES + S_BYTES              # (t || gamma)          = 36 bytes
T2_LEN = T_BYTES + S_BYTES + S_BYTES    # (t || gamma || theta) = 68 bytes


def H(*chunks: bytes) -> bytes:
    h = hashlib.sha256()
    for c in chunks:
        h.update(c)
    return h.digest()


def hash_to_scalar(*chunks: bytes) -> int:
    """c = H(sid || m) reduced into Z_q."""
    return int.from_bytes(H(*chunks), "big") % Q


def kdf(shared_point, length: int) -> bytes:
    """SHA-256 in counter mode, stretched to ``length`` bytes."""
    out = b""
    ctr = 0
    seed = point_to_bytes(shared_point)
    while len(out) < length:
        out += H(seed, ctr.to_bytes(4, "big"))
        ctr += 1
    return out[:length]


def _xor(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))


# --------------------------------------------------------------------------- #
# (t || gamma) and (t || gamma || theta) packing
# --------------------------------------------------------------------------- #
def pack_t_gamma(t: int, gamma: int) -> bytes:
    return t.to_bytes(T_BYTES, "big") + gamma.to_bytes(S_BYTES, "big")


def unpack_t_gamma(blob: bytes):
    t = int.from_bytes(blob[:T_BYTES], "big")
    gamma = int.from_bytes(blob[T_BYTES:T_BYTES + S_BYTES], "big")
    return t, gamma


def pack_t_gamma_theta(t: int, gamma: int, theta: int) -> bytes:
    return pack_t_gamma(t, gamma) + theta.to_bytes(S_BYTES, "big")


def unpack_t_gamma_theta(blob: bytes):
    t, gamma = unpack_t_gamma(blob)
    theta = int.from_bytes(blob[T_BYTES + S_BYTES:T_BYTES + 2 * S_BYTES], "big")
    return t, gamma, theta


# --------------------------------------------------------------------------- #
# Hashed EC-ElGamal
# --------------------------------------------------------------------------- #
def ecelgamal_encrypt(pk, kappa: int, plaintext: bytes):
    """Return the ciphertext component c2; c1 = T0 = kappa * G is shared."""
    return _xor(plaintext, kdf(curve.scalar_mul(kappa, pk), len(plaintext)))


def ecelgamal_decrypt(sk: int, T0, c2: bytes) -> bytes:
    return _xor(c2, kdf(curve.scalar_mul(sk, T0), len(c2)))
