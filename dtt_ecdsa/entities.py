"""The five entities of the DTT-ECDSA message-reporting framework.

    TA      - Trusted Authority      (root of trust, key distribution, registry)
    Vehicle - intelligent connected vehicle (signer)
    TMC     - Traffic Management Center (dynamic threshold t, masks alpha/beta)
    RSU     - Road Side Unit         (aggregator, holds skc)
    Tracer  - tracing authority      (holds skt, runs Protocol 4)

The notation follows Table II of the paper.
"""

from __future__ import annotations

import secrets
from dataclasses import dataclass, field

from . import crypto, curve
from .curve import Q, mul_G, point_sum, point_to_bytes
from .search import exhaustive_subset_search


# --------------------------------------------------------------------------- #
# Wire structures
# --------------------------------------------------------------------------- #
@dataclass
class SignatureShare:
    """delta_i = (sid, m, R_i, a_i, b_i)   -- Protocol 2."""
    sid: bytes
    m: dict
    R: tuple
    a: int
    b: int

    #: |sid| + |G| + 2|Zq| = 16 + 64 + 64 = 144 bytes (Section VI-C).
    WIRE_BYTES = 16 + curve.POINT_BYTES + 2 * curve.SCALAR_BYTES


@dataclass
class AggregateSignature:
    """sigma = (R, sid, m, Vp, z)   -- Protocol 3."""
    R: tuple
    sid: bytes
    m: dict
    Vp: tuple
    z: int
    m_bytes: bytes = b""

    def wire_bytes(self) -> int:
        return (curve.POINT_BYTES + 16 + curve.POINT_BYTES
                + curve.SCALAR_BYTES + len(self.m_bytes))


@dataclass
class SessionCiphertext:
    """(T0, T1, T2) -- the EC-ElGamal encrypted session parameters."""
    T0: tuple
    T1: bytes
    T2: bytes

    def rsu_bytes(self) -> int:      # (T0, T1) -> RSU
        return curve.POINT_BYTES + len(self.T1)

    def tracer_bytes(self) -> int:   # (T0, T2) -> Tracer
        return curve.POINT_BYTES + len(self.T2)


# --------------------------------------------------------------------------- #
# Vehicle
# --------------------------------------------------------------------------- #
@dataclass
class Vehicle:
    """Intelligent connected vehicle: holds ski, publishes pki."""

    vid: str
    plate: str
    sk: int = 0
    pk: tuple = None

    #: vid (8 B) + plate (16 B) + pki (64 B) submitted at registration
    REG_BYTES = 8 + 16 + curve.POINT_BYTES

    def keygen(self):
        """ski <- Zq ; pki = ski * G   (Protocol 1, lines 4-6)."""
        self.sk = curve.rand_scalar()
        self.pk = mul_G(self.sk)
        return self.pk

    def sign_share(self, sid: bytes, m: dict, gamma: int,
                   alpha_i: int, beta_i: int) -> SignatureShare:
        """Protocol 2, lines 4-7 (the on-line part performed by the vehicle).

        ki <- Zq ; Ri = ki * G ; ai = gamma*ki + alpha_i ; bi = gamma*ski + beta_i
        """
        k_i = curve.rand_scalar()
        R_i = mul_G(k_i)
        a_i = (gamma * k_i + alpha_i) % Q
        b_i = (gamma * self.sk + beta_i) % Q
        return SignatureShare(sid=sid, m=m, R=R_i, a=a_i, b=b_i)


# --------------------------------------------------------------------------- #
# TA - Trusted Authority
# --------------------------------------------------------------------------- #
class TA:
    """Root of trust: curve setup, RSU/Tracer key pairs, vehicle registry."""

    #: system parameters broadcast to every entity: G || q || pkR || pkTr
    SYSPARAM_BYTES = curve.POINT_BYTES + curve.SCALAR_BYTES + 2 * curve.POINT_BYTES

    def __init__(self, security_param: int = 128):
        self.security_param = security_param
        self.curve_name = curve.CURVE_NAME
        self.sk_R = 0
        self.pk_R = None
        self.sk_Tr = 0
        self.pk_Tr = None
        self.registry: list[Vehicle] = []   # registration order == vehicle index

    # -- Protocol 1, lines 1-3 ------------------------------------------- #
    def setup(self):
        """curve <- G(lambda); skR, pkR for the RSU; skTr, pkTr for the Tracer."""
        self.sk_R = curve.rand_scalar()
        self.pk_R = mul_G(self.sk_R)
        self.sk_Tr = curve.rand_scalar()
        self.pk_Tr = mul_G(self.sk_Tr)

    # -- Protocol 1, lines 4-6 ------------------------------------------- #
    def register(self, vehicle: Vehicle, proof) -> bool:
        """Certify pki after the proof-of-possession check of assumption A5(i).

        ``proof = (W, u)`` is a Schnorr proof of knowledge of ski; the TA
        accepts iff ``u * G == W + e * pki`` with ``e = H(pki || W)``.
        """
        if vehicle.pk is None or not curve.is_on_curve(vehicle.pk):
            return False
        W, u = proof
        e = crypto.hash_to_scalar(point_to_bytes(vehicle.pk), point_to_bytes(W))
        if mul_G(u) != curve.point_add(W, curve.scalar_mul(e, vehicle.pk)):
            return False
        self.registry.append(vehicle)
        return True

    # -- Protocol 1, lines 7-10 ------------------------------------------ #
    @property
    def public_keys(self):
        return [v.pk for v in self.registry]

    def public_key(self):
        """pk = (pk1, ..., pkn, pkTr, pkR)."""
        return (self.public_keys, self.pk_Tr, self.pk_R)

    def combine_key(self):
        """skc = (pk1, ..., pkn, pkTr, skR)  -- handed to the RSU."""
        return (self.public_keys, self.pk_Tr, self.sk_R)

    def trace_key(self):
        """skt = (pk1, ..., pkn, skTr, pkR)  -- handed to the Tracer."""
        return (self.public_keys, self.sk_Tr, self.pk_R)

    # -- accountability chain (Section V-E) ------------------------------- #
    def identify(self, indices):
        """Map the public keys returned by Trace back to registered identities."""
        return [(i, self.registry[i].vid, self.registry[i].plate) for i in indices]

    # -- byte sizes used by the communication model ----------------------- #
    def skc_bytes(self):
        return len(self.registry) * curve.POINT_BYTES + curve.POINT_BYTES + curve.SCALAR_BYTES

    def skt_bytes(self):
        return len(self.registry) * curve.POINT_BYTES + curve.SCALAR_BYTES + curve.POINT_BYTES

    def pk_bytes(self):
        return len(self.registry) * curve.POINT_BYTES + 2 * curve.POINT_BYTES


# --------------------------------------------------------------------------- #
# TMC - Traffic Management Center
# --------------------------------------------------------------------------- #
class TMC:
    """Outputs the dynamic threshold t and the anti-collusion masks."""

    #: (alpha_i, beta_i) delivered to one signer over a confidential channel
    MASK_BYTES = 2 * curve.SCALAR_BYTES

    def __init__(self, pk_R, pk_Tr):
        self.pk_R = pk_R
        self.pk_Tr = pk_Tr
        self.kappa = 0
        self.gamma = 0
        self.theta = 0
        self.t = 0

    # -- Protocol 2, lines 1-3 ------------------------------------------- #
    def open_session(self, t: int):
        """Pick kappa, gamma, theta, encrypt (t||gamma) and (t||gamma||theta)."""
        self.t = t
        self.kappa = curve.rand_scalar()
        self.gamma = curve.rand_scalar()
        self.theta = curve.rand_scalar()

        T0 = mul_G(self.kappa)
        T1 = crypto.ecelgamal_encrypt(
            self.pk_R, self.kappa, crypto.pack_t_gamma(t, self.gamma))
        T2 = crypto.ecelgamal_encrypt(
            self.pk_Tr, self.kappa, crypto.pack_t_gamma_theta(t, self.gamma, self.theta))
        return SessionCiphertext(T0=T0, T1=T1, T2=T2)

    def allocate_masks(self):
        """{alpha_i} with sum = 0 and {beta_i} with sum = theta (Protocol 2, line 3)."""
        t = self.t
        alphas = [curve.rand_scalar() for _ in range(t - 1)]
        alphas.append((-sum(alphas)) % Q)
        betas = [curve.rand_scalar() for _ in range(t - 1)]
        betas.append((self.theta - sum(betas)) % Q)
        return alphas, betas

    def audit_share(self, share: SignatureShare, pk_i, beta_i) -> bool:
        """Non-repudiation audit of Section V-E: bi*G == gamma*pki + beta_i*G."""
        lhs = mul_G(share.b)
        rhs = curve.point_add(curve.scalar_mul(self.gamma, pk_i), mul_G(beta_i))
        return lhs == rhs


# --------------------------------------------------------------------------- #
# RSU - Road Side Unit (aggregator)
# --------------------------------------------------------------------------- #
class RSU:
    """Holds skc = (pk1..pkn, pkTr, skR) and runs Protocol 3."""

    #: session announcement broadcast to every registered vehicle:
    #: sid (16 B) + H(m) (32 B) + request header (16 B)
    ANNOUNCE_BYTES = 16 + 32 + 16

    def __init__(self, combine_key):
        self.pks, self.pk_Tr, self.sk_R = combine_key
        self.t = 0
        self.gamma = 0

    def open_ciphertext(self, ct: SessionCiphertext):
        """EC-ElGamal decryption of (T0, T1) with skR -> (t, gamma)."""
        blob = crypto.ecelgamal_decrypt(self.sk_R, ct.T0, ct.T1)
        self.t, self.gamma = crypto.unpack_t_gamma(blob)
        return self.t, self.gamma

    # -- Protocol 3 ------------------------------------------------------- #
    def combine(self, shares, m_bytes: bytes) -> AggregateSignature:
        sid = shares[0].sid
        m = shares[0].m

        R = point_sum(s.R for s in shares)                    # R = sum R_i
        a = sum(s.a for s in shares) % Q                      # a = sum a_i
        b = sum(s.b for s in shares) % Q                      # b = sum b_i

        c = crypto.hash_to_scalar(sid, m_bytes)               # c = H(sid || m)
        r_x = R[0] % Q                                        # x-coordinate of R

        z = curve.inv_mod_q(a) * (self.gamma * c + b * r_x) % Q
        V_p = mul_G(b * curve.inv_mod_q(self.gamma) % Q)      # Vp = b * G / gamma

        return AggregateSignature(R=R, sid=sid, m=m, Vp=V_p, z=z, m_bytes=m_bytes)


# --------------------------------------------------------------------------- #
# Tracer
# --------------------------------------------------------------------------- #
@dataclass
class TraceResult:
    success: bool
    indices: list = field(default_factory=list)
    subsets_tested: int = 0
    search_space: int = 0
    t_recovered: int = 0


class Tracer:
    """Holds skt = (pk1..pkn, skTr, pkR) and runs Protocol 4."""

    def __init__(self, trace_key):
        self.pks, self.sk_Tr, self.pk_R = trace_key
        self.t = 0
        self.gamma = 0
        self.theta = 0

    def open_ciphertext(self, ct: SessionCiphertext):
        """EC-ElGamal decryption of (T0, T2) with skTr -> (t, gamma, theta)."""
        blob = crypto.ecelgamal_decrypt(self.sk_Tr, ct.T0, ct.T2)
        self.t, self.gamma, self.theta = crypto.unpack_t_gamma_theta(blob)
        return self.t, self.gamma, self.theta

    # -- Protocol 4 ------------------------------------------------------- #
    def trace(self, sigma: AggregateSignature) -> TraceResult:
        """Strictly exhaustive enumeration of every C subseteq [n] with |C| = t."""
        theta_over_gamma = self.theta * curve.inv_mod_q(self.gamma) % Q
        Theta = mul_G(theta_over_gamma)                       # Theta = theta * G / gamma
        target = curve.point_sub(sigma.Vp, Theta)             # sum pk_i == Vp - Theta

        indices, tested = exhaustive_subset_search(self.pks, target, self.t)
        from .search import search_space
        return TraceResult(
            success=indices is not None,
            indices=indices or [],
            subsets_tested=tested,
            search_space=search_space(len(self.pks), self.t),
            t_recovered=self.t,
        )


# --------------------------------------------------------------------------- #
# Public verification (Corollary 1) - any node can run it
# --------------------------------------------------------------------------- #
def verify_signature(sigma: AggregateSignature) -> bool:
    """u1 = c/z, u2 = rx/z, accept iff u1*G + u2*Vp == R."""
    if sigma.R is None or sigma.Vp is None:
        return False
    if not (1 <= sigma.z < Q):
        return False
    c = crypto.hash_to_scalar(sigma.sid, sigma.m_bytes)
    r_x = sigma.R[0] % Q
    z_inv = curve.inv_mod_q(sigma.z)
    u1 = c * z_inv % Q
    u2 = r_x * z_inv % Q
    return curve.point_add(mul_G(u1), curve.scalar_mul(u2, sigma.Vp)) == sigma.R


def random_plate(rng=None) -> str:
    letters = "ABCDEFGHJKLMNPQRSTUVWXYZ"
    prov = "京沪渝苏浙粤鲁豫"
    pick = secrets.choice if rng is None else rng.choice
    return (pick(prov) + pick(letters)
            + "".join(pick("0123456789") for _ in range(3))
            + "".join(pick(letters) for _ in range(2)))
