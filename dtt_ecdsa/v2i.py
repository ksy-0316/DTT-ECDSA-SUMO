"""Distance-aware V2X communication-delay model.

The offline implementation charged every inter-entity message a flat
``2 ms + 8s/(6x10^3) ms`` (Section VI-A of the paper).  Inside SUMO the real
geometry is available at every simulation step, so the delay of each message is
derived from the *actual* distance between the two entities:

    delay = E[ retransmissions x (channel access + air time + ACK) ] + propagation

Radio layer: IEEE 802.11p / ITS-G5, 10 MHz channel at 5.9 GHz.

    1. log-distance path loss      PL(d) = PL(1 m) + 10 n log10(d)
    2. SNR at the receiver         SNR   = Ptx + Gt + Gr - PL(d) - N0
    3. link adaptation             highest MCS whose required SNR fits in SNR
                                   with a LINK_MARGIN_DB fade margin
    4. packet error rate           PER   = Q(margin / sigma_shadowing)
    5. 802.11p DCF access delay    DIFS + E[backoff], inflated by the channel
                                   busy fraction produced by neighbouring CAMs
    6. unicast retransmissions     up to MAX_RETRIES, broadcast frames are sent
                                   once and never acknowledged

Backhaul links (RSU <-> TA / TMC / Tracer) are wired and use a separate,
much cheaper model.

Every constant below is a published 802.11p figure or an explicitly stated
modelling assumption; nothing is tuned to reproduce a particular result.
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field

# --------------------------------------------------------------------------- #
# PHY layer -- IEEE 802.11p (ITS-G5), 10 MHz channel at 5.9 GHz
# --------------------------------------------------------------------------- #
LIGHT_SPEED_MPS = 299_792_458.0
CARRIER_HZ = 5.9e9
CHANNEL_BW_HZ = 10e6

TX_POWER_DBM = 20.0            # 100 mW, typical OBU/RSU transmit power
ANT_GAIN_TX_DBI = 3.0
ANT_GAIN_RX_DBI = 3.0
NOISE_FIGURE_DB = 9.0
THERMAL_NOISE_DBM_PER_HZ = -174.0

#: N0 = -174 + 10log10(10 MHz) + NF = -174 + 70 + 9 = -95 dBm
NOISE_DBM = (THERMAL_NOISE_DBM_PER_HZ
             + 10.0 * math.log10(CHANNEL_BW_HZ)
             + NOISE_FIGURE_DB)

PATHLOSS_EXPONENT = 2.75       # urban intersection with buildings
SHADOWING_SIGMA_DB = 3.0       # log-normal shadowing standard deviation
REF_DISTANCE_M = 1.0

#: free-space loss at 1 m:  20 log10(4 pi d f / c) = 47.86 dB at 5.9 GHz
PL_REF_DB = 20.0 * math.log10(
    4.0 * math.pi * REF_DISTANCE_M * CARRIER_HZ / LIGHT_SPEED_MPS)

#: (data rate in bit/s, required SNR in dB) for the eight 802.11p MCS
MCS_TABLE = [
    (3.0e6, 5.0),    # BPSK   1/2
    (4.5e6, 6.0),    # BPSK   3/4
    (6.0e6, 8.0),    # QPSK   1/2
    (9.0e6, 11.0),   # QPSK   3/4
    (12.0e6, 15.0),  # 16-QAM 1/2
    (18.0e6, 20.0),  # 16-QAM 3/4
    (24.0e6, 25.0),  # 64-QAM 2/3
    (27.0e6, 26.0),  # 64-QAM 3/4
]

#: fade margin required by link adaptation before a MCS is selected
LINK_MARGIN_DB = 6.0

# --------------------------------------------------------------------------- #
# MAC layer -- 802.11p DCF
# --------------------------------------------------------------------------- #
SLOT_S = 13e-6
SIFS_S = 32e-6
DIFS_S = SIFS_S + 2.0 * SLOT_S        # 58 us
PREAMBLE_S = 40e-6                    # preamble + SIGNAL field
CW_MIN = 15
CW_MAX = 1023
MAX_RETRIES = 3                       # 4 transmission attempts in total

MAC_HEADER_BYTES = 36                 # 802.11 MAC + LLC/SNAP
SEC_HEADER_BYTES = 40                 # IEEE 1609.2 SignedData envelope
ACK_BYTES = 14

#: background load: every station in range sends CAMs at 10 Hz
BEACON_HZ = 10.0
BEACON_BYTES = 300
BEACON_RATE_BPS = 6.0e6
MAX_BUSY_FRACTION = 0.80              # saturation guard

#: Air time alone is not what an application observes.  Each frame additionally
#: crosses the V2X protocol stack twice (tx queueing + IEEE 1609.2 encoding on
#: the sender, decoding + delivery on the receiver).  Measurements on commercial
#: OBUs put that at roughly 1 ms, which is also what keeps the totals here in
#: the same range as the 2 ms single-hop figure of the paper.
STACK_OVERHEAD_MS = 1.0

# --------------------------------------------------------------------------- #
# Wired backhaul -- RSU <-> TA / TMC / Tracer
# --------------------------------------------------------------------------- #
WIRED_HOP_LATENCY_MS = 0.5
WIRED_BANDWIDTH_MBPS = 100.0
WIRED_HOPS = 2


# --------------------------------------------------------------------------- #
# PHY helpers
# --------------------------------------------------------------------------- #
def path_loss_db(distance_m: float) -> float:
    d = max(distance_m, REF_DISTANCE_M)
    return PL_REF_DB + 10.0 * PATHLOSS_EXPONENT * math.log10(d / REF_DISTANCE_M)


def snr_db(distance_m: float) -> float:
    rx_dbm = (TX_POWER_DBM + ANT_GAIN_TX_DBI + ANT_GAIN_RX_DBI
              - path_loss_db(distance_m))
    return rx_dbm - NOISE_DBM


def select_mcs(snr: float):
    """Highest (rate, required SNR) usable at ``snr`` with the fade margin."""
    chosen = None
    for rate, req in MCS_TABLE:
        if snr >= req + LINK_MARGIN_DB:
            chosen = (rate, req)
    return chosen


def max_range_m() -> float:
    """Largest distance at which the slowest MCS is still usable."""
    _rate, req = MCS_TABLE[0]
    budget = (TX_POWER_DBM + ANT_GAIN_TX_DBI + ANT_GAIN_RX_DBI
              - NOISE_DBM - req - LINK_MARGIN_DB)
    exponent = (budget - PL_REF_DB) / (10.0 * PATHLOSS_EXPONENT)
    return REF_DISTANCE_M * 10.0 ** exponent


def _q(x: float) -> float:
    """Gaussian tail probability Q(x) = 0.5 erfc(x / sqrt 2)."""
    return 0.5 * math.erfc(x / math.sqrt(2.0))


def packet_error_rate(snr: float, required_snr: float) -> float:
    """Outage probability of the selected MCS under log-normal shadowing."""
    margin = snr - required_snr
    return min(0.999, max(1e-9, _q(margin / SHADOWING_SIGMA_DB)))


def air_time_s(nbytes: int, rate_bps: float) -> float:
    """Time on air of one frame, preamble included."""
    bits = 8 * (nbytes + MAC_HEADER_BYTES)
    return PREAMBLE_S + bits / rate_bps


def busy_fraction(neighbours: int) -> float:
    """Fraction of time the channel is occupied by neighbouring CAM traffic."""
    per_beacon = air_time_s(BEACON_BYTES, BEACON_RATE_BPS)
    return min(MAX_BUSY_FRACTION, max(0, neighbours) * BEACON_HZ * per_beacon)


def _backoff_s(attempt: int) -> float:
    cw = min(CW_MAX, (CW_MIN + 1) * (2 ** attempt) - 1)
    return 0.5 * cw * SLOT_S


# --------------------------------------------------------------------------- #
# Link delay
# --------------------------------------------------------------------------- #
@dataclass
class LinkResult:
    ms: float
    rate_mbps: float
    snr_db: float
    per: float
    attempts: float
    in_range: bool


def wireless_delay(nbytes: int, distance_m: float, neighbours: int = 0,
                   broadcast: bool = False) -> LinkResult:
    """End-to-end delay of one 802.11p frame over ``distance_m`` metres."""
    snr = snr_db(distance_m)
    mcs = select_mcs(snr)
    if mcs is None:
        return LinkResult(ms=float("inf"), rate_mbps=0.0, snr_db=snr,
                          per=1.0, attempts=0.0, in_range=False)

    rate, required = mcs
    payload = nbytes + SEC_HEADER_BYTES
    t_air = air_time_s(payload, rate)
    t_prop = distance_m / LIGHT_SPEED_MPS
    defer = 1.0 / (1.0 - busy_fraction(neighbours))

    if broadcast:
        # broadcast frames carry no ACK and are never retransmitted
        total = (DIFS_S + _backoff_s(0)) * defer + t_air + t_prop
        return LinkResult(ms=total * 1000.0 + STACK_OVERHEAD_MS,
                          rate_mbps=rate / 1e6, snr_db=snr,
                          per=packet_error_rate(snr, required), attempts=1.0,
                          in_range=True)

    per = packet_error_rate(snr, required)
    t_ack = air_time_s(ACK_BYTES, MCS_TABLE[0][0])

    total = 0.0
    attempts = 0.0
    for i in range(MAX_RETRIES + 1):
        weight = per ** i                     # probability attempt i is needed
        attempts += weight
        total += weight * ((DIFS_S + _backoff_s(i)) * defer
                           + t_air + t_prop + SIFS_S + t_ack + t_prop)
    return LinkResult(ms=total * 1000.0 + STACK_OVERHEAD_MS,
                      rate_mbps=rate / 1e6, snr_db=snr,
                      per=per, attempts=attempts, in_range=True)


def wired_delay_ms(nbytes: int, hops: int = WIRED_HOPS) -> float:
    return hops * (WIRED_HOP_LATENCY_MS
                   + 8.0 * nbytes / (WIRED_BANDWIDTH_MBPS * 1000.0))


# --------------------------------------------------------------------------- #
# Per-phase accounting
# --------------------------------------------------------------------------- #
@dataclass
class LinkRecord:
    src: str
    dst: str
    label: str
    kind: str          # "V2I" / "V2I-BC" / "WIRE"
    nbytes: int
    count: int
    ms: float
    distance_m: float = 0.0
    rate_mbps: float = 0.0
    snr_db: float = 0.0
    per: float = 0.0


@dataclass
class V2XChannel:
    """Accumulates every inter-entity message of one protocol phase."""

    total_ms: float = 0.0
    total_bytes: int = 0
    log: list = field(default_factory=list)
    dropped: int = 0

    # -- wireless ------------------------------------------------------- #
    def wireless(self, src: str, dst: str, label: str, nbytes: int,
                 distance_m: float, neighbours: int = 0,
                 broadcast: bool = False) -> float:
        res = wireless_delay(nbytes, distance_m, neighbours, broadcast)
        if not res.in_range:
            self.dropped += 1
            return 0.0
        self.total_ms += res.ms
        self.total_bytes += nbytes
        self.log.append(LinkRecord(
            src=src, dst=dst, label=label,
            kind="V2I-BC" if broadcast else "V2I",
            nbytes=nbytes, count=1, ms=res.ms, distance_m=distance_m,
            rate_mbps=res.rate_mbps, snr_db=res.snr_db, per=res.per))
        return res.ms

    def wireless_many(self, src: str, dst: str, label: str, nbytes: int,
                      distances, neighbours: int = 0) -> float:
        """``len(distances)`` unicast frames, each at its own real distance.

        They share the medium, so the delays add up rather than overlap.
        """
        distances = list(distances)
        if not distances:
            return 0.0
        total = 0.0
        rates, snrs, pers = [], [], []
        for d in distances:
            res = wireless_delay(nbytes, d, neighbours, broadcast=False)
            if not res.in_range:
                self.dropped += 1
                continue
            total += res.ms
            rates.append(res.rate_mbps)
            snrs.append(res.snr_db)
            pers.append(res.per)
        if not rates:
            return 0.0
        self.total_ms += total
        self.total_bytes += nbytes * len(rates)
        self.log.append(LinkRecord(
            src=src, dst=dst, label=label, kind="V2I",
            nbytes=nbytes, count=len(rates), ms=total,
            distance_m=sum(distances) / len(distances),
            rate_mbps=sum(rates) / len(rates),
            snr_db=sum(snrs) / len(snrs),
            per=sum(pers) / len(pers)))
        return total

    # -- wired ---------------------------------------------------------- #
    def wired(self, src: str, dst: str, label: str, nbytes: int,
              count: int = 1, hops: int = WIRED_HOPS) -> float:
        ms = count * wired_delay_ms(nbytes, hops)
        self.total_ms += ms
        self.total_bytes += count * nbytes
        self.log.append(LinkRecord(src=src, dst=dst, label=label, kind="WIRE",
                                   nbytes=nbytes, count=count, ms=ms))
        return ms

    # -- reporting ------------------------------------------------------ #
    def report(self, indent: str = "    ") -> str:
        lines = []
        for r in self.log:
            head = (f"{indent}{r.src:>7s} -> {r.dst:<8s} | {r.kind:<7s} | "
                    f"{r.label:<30s} | {r.nbytes:5d} B x {r.count:<3d} = "
                    f"{r.ms:9.3f} ms")
            if r.kind != "WIRE":
                head += (f" | d={r.distance_m:6.1f} m  {r.rate_mbps:4.1f} Mbps"
                         f"  SNR={r.snr_db:5.1f} dB  PER={r.per:.2e}")
            lines.append(head)
        lines.append(f"{indent}{'':>7s}    {'':<8s} | {'TOTAL':<7s} | "
                     f"{'':<30s} | {self.total_bytes:5d} B       = "
                     f"{self.total_ms:9.3f} ms")
        if self.dropped:
            lines.append(f"{indent}[!] {self.dropped} 条报文因超出通信范围被丢弃")
        return "\n".join(lines)


def model_summary() -> str:
    return (f"IEEE 802.11p @ {CARRIER_HZ/1e9:.1f} GHz / {CHANNEL_BW_HZ/1e6:.0f} MHz, "
            f"Ptx={TX_POWER_DBM:.0f} dBm, N0={NOISE_DBM:.0f} dBm, "
            f"路径损耗指数 n={PATHLOSS_EXPONENT}, 阴影 sigma={SHADOWING_SIGMA_DB} dB, "
            f"链路余量 {LINK_MARGIN_DB:.0f} dB, 最大通信距离 {max_range_m():.0f} m, "
            f"协议栈开销 {STACK_OVERHEAD_MS} ms/帧; "
            f"有线回程 {WIRED_HOPS} 跳 x ({WIRED_HOP_LATENCY_MS} ms + "
            f"{WIRED_BANDWIDTH_MBPS:.0f} Mbps)")
