"""DTT-ECDSA driven by the live SUMO simulation.

The scheme itself is unchanged -- the four protocols, the masking relations and
the strictly exhaustive tracing are exactly those of the offline implementation.
What changes is *where the numbers come from*:

    * registration happens progressively, as vehicles drive into RSU range;
    * the threshold t is decided by the TMC from the severity of the crash;
    * every inter-entity message is charged the delay its **real geometry**
      implies (``v2i.V2XChannel``), not a flat constant.

``LinkContext`` is the only coupling to TraCI: the scheme asks it for the
current vehicle-to-RSU distance and for the number of stations sharing the
channel.  ``StaticLinkContext`` provides the same interface without SUMO, so
``selftest.py`` and the unit tests run anywhere.
"""

from __future__ import annotations

import math
import random
import time
from dataclasses import dataclass, field

from . import curve, crypto, message as msg
from .curve import Q, mul_G, point_to_bytes
from .entities import (TA, RSU, TMC, Tracer, Vehicle, SignatureShare,
                       random_plate, verify_signature)
from .v2i import V2XChannel, max_range_m

#: radius inside which a vehicle can talk to the RSU (PHY limited)
RSU_RANGE_M = max_range_m()

#: severity of the crash -> threshold chosen by the TMC
SEVERITY_THRESHOLD = {
    "minor": 3,
    "moderate": 4,
    "severe": 6,
    "critical": 8,
}


def threshold_from_severity(severity: str, candidates: int) -> int:
    """TMC policy: the worse the crash, the more independent witnesses."""
    t = SEVERITY_THRESHOLD.get(severity, 4)
    return max(1, min(t, candidates))


def classify_severity(involved: int, blocked: int) -> str:
    """Severity as the TMC infers it from what the RSU reports."""
    if involved >= 4 or blocked >= 30:
        return "critical"
    if involved >= 3 or blocked >= 20:
        return "severe"
    if involved >= 2 or blocked >= 8:
        return "moderate"
    return "minor"


# --------------------------------------------------------------------------- #
# Link context
# --------------------------------------------------------------------------- #
class LinkContext:
    """Geometry source for the communication model."""

    def distance(self, sumo_id: str) -> float:
        """Metres between that vehicle and the RSU, right now."""
        raise NotImplementedError

    def neighbour_count(self) -> int:
        """Stations currently sharing the channel (CAM background load)."""
        raise NotImplementedError


@dataclass
class StaticLinkContext(LinkContext):
    """Offline stand-in: fixed distances, fixed channel load."""

    distances: dict = field(default_factory=dict)
    default_distance_m: float = 60.0
    neighbours: int = 20

    def distance(self, sumo_id: str) -> float:
        return self.distances.get(sumo_id, self.default_distance_m)

    def neighbour_count(self) -> int:
        return self.neighbours


# --------------------------------------------------------------------------- #
# Phase bookkeeping
# --------------------------------------------------------------------------- #
@dataclass
class PhaseTiming:
    """compute + communication, in milliseconds, as required by the paper."""

    name: str
    compute_ms: float
    channel: V2XChannel

    @property
    def comm_ms(self) -> float:
        return self.channel.total_ms

    @property
    def total_ms(self) -> float:
        return self.compute_ms + self.channel.total_ms

    def line(self) -> str:
        return (f"{self.name}: 计算 {self.compute_ms:.3f} ms + 通信 "
                f"{self.comm_ms:.3f} ms = {self.total_ms:.3f} ms")


@dataclass
class RegisteredVehicle:
    index: int
    sumo_id: str
    vehicle: Vehicle
    distance_m: float
    sim_time: float


# --------------------------------------------------------------------------- #
# The session
# --------------------------------------------------------------------------- #
class VANETReportSession:
    """One crash-reporting session played out on top of the SUMO run."""

    def __init__(self, n: int, link: LinkContext | None = None,
                 rng: random.Random | None = None, session_counter: int = 1):
        if n < 1:
            raise ValueError("n 必须 >= 1")
        self.n = n
        self.link = link or StaticLinkContext()
        self.rng = rng or random.Random()
        self.session_counter = session_counter

        self.ta = TA()
        self.rsu: RSU | None = None
        self.tmc: TMC | None = None
        self.tracer: Tracer | None = None

        self.registered: list[RegisteredVehicle] = []

        # phase 1 is accumulated over many simulation steps
        self._t1_compute = 0.0
        self._t1_channel = V2XChannel()
        self._setup_done = False
        self.timing: dict[str, PhaseTiming] = {}

        # phase 2/3/4 state
        self.t = 0
        self.severity = ""
        self.signer_indices: list[int] = []
        self.message: dict | None = None
        self.m_bytes = b""
        self.sid = b""
        self.shares: list[SignatureShare] = []
        self.ciphertext = None
        self.sigma = None
        self.trace_result = None
        self.verified = False

    # ------------------------------------------------------------------ #
    # Phase 1 -- system initialisation (Protocol 1), spread over the run
    # ------------------------------------------------------------------ #
    def setup_authority(self):
        """TA generates the curve parameters and the RSU / Tracer key pairs."""
        t0 = time.perf_counter()
        self.ta.setup()
        self._t1_compute += (time.perf_counter() - t0) * 1000.0
        self._setup_done = True

    @property
    def registration_open(self) -> bool:
        return self._setup_done and len(self.registered) < self.n

    def is_registered(self, sumo_id: str) -> bool:
        return any(r.sumo_id == sumo_id for r in self.registered)

    def _prove_possession(self, v: Vehicle):
        """Schnorr proof of knowledge of ski (assumption A5(i))."""
        w = curve.rand_scalar()
        W = mul_G(w)
        e = crypto.hash_to_scalar(point_to_bytes(v.pk), point_to_bytes(W))
        return (W, (w + e * v.sk) % Q)

    def register_vehicle(self, sumo_id: str, sim_time: float = 0.0) -> bool:
        """Register one vehicle that has just entered RSU range.

        Both legs are charged at the vehicle's real distance: the RSU beacons
        the system parameters down, the vehicle sends pki plus its proof up.
        """
        if not self.registration_open or self.is_registered(sumo_id):
            return False

        distance = self.link.distance(sumo_id)
        if distance > RSU_RANGE_M:
            return False
        neighbours = self.link.neighbour_count()

        idx = len(self.registered)
        v = Vehicle(vid=f"VEH-{idx:03d}", plate=random_plate(self.rng))

        t0 = time.perf_counter()
        v.keygen()
        proof = self._prove_possession(v)
        accepted = self.ta.register(v, proof)
        self._t1_compute += (time.perf_counter() - t0) * 1000.0
        if not accepted:
            return False

        ch = self._t1_channel
        ch.wireless("RSU", f"V{idx}", "系统参数 (G,q,pkR,pkTr)",
                    TA.SYSPARAM_BYTES, distance, neighbours)
        ch.wireless(f"V{idx}", "RSU", "注册请求 (pki + Schnorr 证明)",
                    Vehicle.REG_BYTES + 2 * curve.SCALAR_BYTES,
                    distance, neighbours)

        self.registered.append(RegisteredVehicle(
            index=idx, sumo_id=sumo_id, vehicle=v,
            distance_m=distance, sim_time=sim_time))
        return True

    def finish_registration(self) -> PhaseTiming:
        """The n-th vehicle is in: TA hands out skc / skt / pk over the backhaul."""
        if len(self.registered) < self.n:
            raise RuntimeError(
                f"仅注册了 {len(self.registered)}/{self.n} 辆车，无法完成初始化")

        t0 = time.perf_counter()
        combine_key = self.ta.combine_key()
        trace_key = self.ta.trace_key()
        public_key = self.ta.public_key()
        self.rsu = RSU(combine_key)
        self.tracer = Tracer(trace_key)
        self.tmc = TMC(self.ta.pk_R, self.ta.pk_Tr)
        self._t1_compute += (time.perf_counter() - t0) * 1000.0

        ch = self._t1_channel
        ch.wired("TA", "RSU", "组合密钥 skc", self.ta.skc_bytes())
        ch.wired("TA", "Tracer", "追踪密钥 skt", self.ta.skt_bytes())
        ch.wired("TA", "TMC", "系统公钥 pk", self.ta.pk_bytes())
        _ = public_key

        self.timing["init"] = PhaseTiming("初始化", self._t1_compute, ch)
        return self.timing["init"]

    # ------------------------------------------------------------------ #
    # Phase 2 -- signature generation (Protocol 2)
    # ------------------------------------------------------------------ #
    def select_signers(self, candidates, t: int) -> list[int]:
        """t signers drawn at random from the witnesses that are registered."""
        pool = list(candidates)
        if len(pool) < t:
            raise ValueError(f"候选目击车辆 {len(pool)} 辆，少于门限 t={t}")
        return sorted(self.rng.sample(pool, t))

    def generate_signature(self, message: dict, severity: str,
                           candidates, t: int | None = None) -> PhaseTiming:
        """RSU announces the session, the TMC opens it, the signers answer."""
        if self.rsu is None:
            raise RuntimeError("初始化阶段尚未完成")

        candidates = list(candidates)
        self.severity = severity
        if t is None:
            t = threshold_from_severity(severity, len(candidates))
        self.t = t
        self.signer_indices = self.select_signers(candidates, t)

        self.message = message
        self.m_bytes = msg.serialize(message)
        self.sid = msg.new_sid(self.session_counter)

        ch = V2XChannel()
        neighbours = self.link.neighbour_count()
        signers = [self.registered[i] for i in self.signer_indices]
        distances = [self._distance_now(r) for r in signers]

        # RSU announces the reporting session -- one broadcast frame reaches
        # every vehicle in range, so it is charged once, not n times.
        bc_distance = max(distances) if distances else RSU_RANGE_M
        ch.wireless("RSU", "所有车辆", "上报会话公告 (广播)",
                    RSU.ANNOUNCE_BYTES, bc_distance, neighbours, broadcast=True)

        t0 = time.perf_counter()
        self.ciphertext = self.tmc.open_session(t)
        alphas, betas = self.tmc.allocate_masks()
        compute = (time.perf_counter() - t0) * 1000.0

        ch.wired("TMC", "RSU", "会话密文 (T0,T1)", self.ciphertext.rsu_bytes())
        ch.wired("TMC", "Tracer", "会话密文 (T0,T2)", self.ciphertext.tracer_bytes())
        # masks travel TMC -> RSU over the backhaul, then RSU -> vehicle by radio
        ch.wired("TMC", "RSU", "掩码 (alpha_i,beta_i) 转发", TMC.MASK_BYTES, count=t)
        ch.wireless_many("RSU", "签名车辆", "掩码 (alpha_i,beta_i)",
                         TMC.MASK_BYTES, distances, neighbours)

        t0 = time.perf_counter()
        self.rsu.open_ciphertext(self.ciphertext)
        self.tracer.open_ciphertext(self.ciphertext)
        gamma = self.tmc.gamma
        self.shares = [r.vehicle.sign_share(self.sid, message, gamma, a, b)
                       for r, a, b in zip(signers, alphas, betas)]
        compute += (time.perf_counter() - t0) * 1000.0

        ch.wireless_many("签名车辆", "RSU", "部分签名 delta_i",
                         SignatureShare.WIRE_BYTES, distances, neighbours)

        self.timing["sign"] = PhaseTiming("签名生成", compute, ch)
        return self.timing["sign"]

    def _distance_now(self, reg: RegisteredVehicle) -> float:
        """Current distance, falling back to the registration one if gone."""
        d = self.link.distance(reg.sumo_id)
        if d is None or d <= 0.0 or d > RSU_RANGE_M:
            return min(reg.distance_m, RSU_RANGE_M)
        return d

    # ------------------------------------------------------------------ #
    # Phase 3 -- signature aggregation (Protocol 3)
    # ------------------------------------------------------------------ #
    def combine_signature(self) -> PhaseTiming:
        ch = V2XChannel()
        t0 = time.perf_counter()
        self.sigma = self.rsu.combine(self.shares, self.m_bytes)
        self.verified = verify_signature(self.sigma)
        compute = (time.perf_counter() - t0) * 1000.0

        ch.wireless("RSU", "所有车辆", "聚合签名 sigma (广播)",
                    self.sigma.wire_bytes(), RSU_RANGE_M,
                    self.link.neighbour_count(), broadcast=True)
        ch.wired("RSU", "TMC", "事故上报 sigma", self.sigma.wire_bytes())

        self.timing["combine"] = PhaseTiming("签名聚合", compute, ch)
        return self.timing["combine"]

    # ------------------------------------------------------------------ #
    # Phase 4 -- tracing (Protocol 4), strictly exhaustive
    # ------------------------------------------------------------------ #
    def trace_signature(self) -> PhaseTiming:
        ch = V2XChannel()
        ch.wired("RSU", "Tracer", "待追踪签名 sigma", self.sigma.wire_bytes())

        t0 = time.perf_counter()
        self.trace_result = self.tracer.trace(self.sigma)
        compute = (time.perf_counter() - t0) * 1000.0

        n_found = len(self.trace_result.indices)
        ch.wired("Tracer", "TA", "还原出的公钥集合",
                 n_found * curve.POINT_BYTES or curve.POINT_BYTES)
        ch.wired("TA", "Tracer", "身份映射 (ID, 车牌)",
                 n_found * (8 + 16) or 24)

        self.timing["trace"] = PhaseTiming("签名追踪", compute, ch)
        return self.timing["trace"]

    # ------------------------------------------------------------------ #
    # Results
    # ------------------------------------------------------------------ #
    def ground_truth(self) -> list[int]:
        return list(self.signer_indices)

    def traced_indices(self) -> list[int]:
        return list(self.trace_result.indices) if self.trace_result else []

    def trace_correct(self) -> bool:
        return bool(self.trace_result and self.trace_result.success
                    and self.traced_indices() == self.ground_truth())

    def identities(self, indices=None):
        idx = self.traced_indices() if indices is None else list(indices)
        rows = []
        for i in idx:
            r = self.registered[i]
            rows.append((i, r.vehicle.vid, r.vehicle.plate, r.sumo_id))
        return rows

    def search_space(self) -> int:
        return math.comb(self.n, self.t) if self.t else 0

    def phase_totals(self) -> dict:
        """The three timings the paper reports, in milliseconds."""
        init = self.timing["init"].total_ms
        sign = (self.timing["sign"].total_ms + self.timing["combine"].total_ms)
        trace = self.timing["trace"].total_ms
        return {"init_ms": init, "sign_ms": sign, "trace_ms": trace,
                "total_ms": init + sign + trace}
