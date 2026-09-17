"""secp256r1 (NIST P-256) elliptic curve arithmetic for DTT-ECDSA.

Pure-python implementation written from scratch, as described in Section VI-A
of the paper ("The cryptographic protocol is implemented from scratch over
secp256r1").

Two coordinate systems are used:

* affine ``(x, y)`` (``None`` denotes the point at infinity) for the public API;
* Jacobian ``(X, Y, Z)`` internally, so that scalar multiplication and the
  exhaustive tracing search need only a single modular inversion (or none).

A fixed-base 4-bit comb table for the generator ``G`` is built lazily, because
``k * G`` is by far the most frequent operation in the scheme
(``Ri = ki * G``, ``pki = ski * G``, ``Vp = b * G / gamma``, ``Theta = theta * G / gamma``).
"""

from __future__ import annotations

import secrets

# --------------------------------------------------------------------------- #
# Domain parameters of secp256r1 / NIST P-256 / prime256v1
# --------------------------------------------------------------------------- #
P = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
A = P - 3
B = 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B
GX = 0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296
GY = 0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5
# group order q (called `n` in the standard, `q` in the paper)
Q = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551

G = (GX, GY)

CURVE_NAME = "secp256r1"
FIELD_BYTES = 32
POINT_BYTES = 2 * FIELD_BYTES  # uncompressed x || y
SCALAR_BYTES = 32


# --------------------------------------------------------------------------- #
# Scalar helpers (arithmetic modulo the group order q)
# --------------------------------------------------------------------------- #
def rand_scalar() -> int:
    """Uniform element of Z_q^*."""
    while True:
        k = secrets.randbelow(Q)
        if k != 0:
            return k


def inv_mod_q(x: int) -> int:
    return pow(x % Q, Q - 2, Q)


def int_to_bytes(x: int, length: int = FIELD_BYTES) -> bytes:
    return int(x).to_bytes(length, "big")


# --------------------------------------------------------------------------- #
# Affine arithmetic
# --------------------------------------------------------------------------- #
def is_on_curve(pt) -> bool:
    if pt is None:
        return True
    x, y = pt
    return (y * y - (x * x * x + A * x + B)) % P == 0


def point_neg(pt):
    if pt is None:
        return None
    x, y = pt
    return (x, (-y) % P)


def point_add(p1, p2):
    """Affine addition; ``None`` is the point at infinity."""
    if p1 is None:
        return p2
    if p2 is None:
        return p1
    x1, y1 = p1
    x2, y2 = p2
    if x1 == x2:
        if (y1 + y2) % P == 0:
            return None
        lam = (3 * x1 * x1 + A) * pow(2 * y1, P - 2, P) % P
    else:
        lam = (y2 - y1) * pow(x2 - x1, P - 2, P) % P
    x3 = (lam * lam - x1 - x2) % P
    y3 = (lam * (x1 - x3) - y1) % P
    return (x3, y3)


def point_sub(p1, p2):
    return point_add(p1, point_neg(p2))


def point_sum(points):
    acc = None
    for pt in points:
        acc = point_add(acc, pt)
    return acc


# --------------------------------------------------------------------------- #
# Jacobian arithmetic  (X, Y, Z) ~ affine (X/Z^2, Y/Z^3);  Z == 0 is infinity
# --------------------------------------------------------------------------- #
JAC_INF = (1, 1, 0)


def jac_double(j):
    X1, Y1, Z1 = j
    if Z1 == 0 or Y1 == 0:
        return JAC_INF
    # "dbl-2001-b" for a = -3
    delta = Z1 * Z1 % P
    gamma = Y1 * Y1 % P
    beta = X1 * gamma % P
    alpha = 3 * (X1 - delta) * (X1 + delta) % P
    X3 = (alpha * alpha - 8 * beta) % P
    Z3 = ((Y1 + Z1) * (Y1 + Z1) - gamma - delta) % P
    Y3 = (alpha * (4 * beta - X3) - 8 * gamma * gamma) % P
    return (X3, Y3, Z3)


def jac_add_affine(j, pt):
    """Mixed Jacobian + affine addition (``madd``)."""
    if pt is None:
        return j
    X1, Y1, Z1 = j
    if Z1 == 0:
        return (pt[0], pt[1], 1)
    x2, y2 = pt
    Z1Z1 = Z1 * Z1 % P
    U2 = x2 * Z1Z1 % P
    S2 = y2 * Z1 * Z1Z1 % P
    H = (U2 - X1) % P
    r = (S2 - Y1) % P
    if H == 0:
        if r == 0:
            return jac_double(j)
        return JAC_INF
    HH = H * H % P
    HHH = H * HH % P
    V = X1 * HH % P
    X3 = (r * r - HHH - 2 * V) % P
    Y3 = (r * (V - X3) - Y1 * HHH) % P
    Z3 = Z1 * H % P
    return (X3, Y3, Z3)


def jac_add(j1, j2):
    X1, Y1, Z1 = j1
    X2, Y2, Z2 = j2
    if Z1 == 0:
        return j2
    if Z2 == 0:
        return j1
    Z1Z1 = Z1 * Z1 % P
    Z2Z2 = Z2 * Z2 % P
    U1 = X1 * Z2Z2 % P
    U2 = X2 * Z1Z1 % P
    S1 = Y1 * Z2 * Z2Z2 % P
    S2 = Y2 * Z1 * Z1Z1 % P
    H = (U2 - U1) % P
    rr = (S2 - S1) % P
    if H == 0:
        if rr == 0:
            return jac_double(j1)
        return JAC_INF
    HH = H * H % P
    HHH = H * HH % P
    V = U1 * HH % P
    X3 = (rr * rr - HHH - 2 * V) % P
    Y3 = (rr * (V - X3) - S1 * HHH) % P
    Z3 = Z1 * Z2 * H % P
    return (X3, Y3, Z3)


def jac_to_affine(j):
    X, Y, Z = j
    if Z == 0:
        return None
    zi = pow(Z, P - 2, P)
    zi2 = zi * zi % P
    return (X * zi2 % P, Y * zi2 % P * zi % P)


# --------------------------------------------------------------------------- #
# Scalar multiplication
# --------------------------------------------------------------------------- #
def scalar_mul(k: int, pt):
    """Generic ``k * pt`` (left-to-right double-and-add in Jacobian)."""
    k %= Q
    if k == 0 or pt is None:
        return None
    acc = JAC_INF
    for bit in bin(k)[2:]:
        acc = jac_double(acc)
        if bit == "1":
            acc = jac_add_affine(acc, pt)
    return jac_to_affine(acc)


_COMB_W = 4
_COMB_D = 1 << _COMB_W          # 16
_COMB_ROWS = 256 // _COMB_W     # 64
_COMB_TABLE = None


def _build_comb_table():
    """table[j][d-1] = d * 16^j * G  (affine), for d = 1..15."""
    table = []
    base = G
    for _ in range(_COMB_ROWS):
        row = []
        acc = None
        for _d in range(1, _COMB_D):
            acc = point_add(acc, base)
            row.append(acc)
        table.append(row)
        base = point_add(row[_COMB_D - 2], base)  # 16 * base
    return table


def mul_G(k: int):
    """Fixed-base ``k * G`` using a 4-bit comb table."""
    global _COMB_TABLE
    k %= Q
    if k == 0:
        return None
    if _COMB_TABLE is None:
        _COMB_TABLE = _build_comb_table()
    acc = JAC_INF
    j = 0
    while k:
        d = k & 0xF
        if d:
            acc = jac_add_affine(acc, _COMB_TABLE[j][d - 1])
        k >>= _COMB_W
        j += 1
    return jac_to_affine(acc)


# --------------------------------------------------------------------------- #
# Serialisation (used both for hashing and for the communication-cost model)
# --------------------------------------------------------------------------- #
def point_to_bytes(pt) -> bytes:
    """Uncompressed 64-byte encoding x || y (infinity -> 64 zero bytes)."""
    if pt is None:
        return b"\x00" * POINT_BYTES
    return int_to_bytes(pt[0]) + int_to_bytes(pt[1])


# --------------------------------------------------------------------------- #
# Warm-up: build the fixed-base comb table at import time so that its one-off
# construction cost is never charged to a timed protocol phase.
# --------------------------------------------------------------------------- #
mul_G(1)

