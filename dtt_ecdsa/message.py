"""The reported message m, built from the live SUMO crash data.

The five fields required by the scheme are kept exactly as in the offline
implementation --

    Message Type | Message ID | Timestamp | Location | Event Details

-- but their contents are no longer random: they are filled from what the
witness vehicles actually observe in the simulation (crash coordinates, the
lane and road of the event, the vehicles involved, how many vehicles are
blocked, the speed the witness was travelling at, ...).
"""

from __future__ import annotations

import json
import random
import secrets
import time
from datetime import datetime, timezone

#: message types of the DTT-ECDSA reporting service, with their ID code
MESSAGE_TYPES = {
    "EMERGENCY_HAZARD_WARNING": "HW",
    "TRAFFIC_CONGESTION_REPORT": "TC",
    "COLLISION_RISK_WARNING": "CR",
    "STATIONARY_VEHICLE_ALERT": "SA",
    "ROAD_WORKS_NOTIFICATION": "RW",
    "ADVERSE_WEATHER_ALERT": "AW",
}

#: SUMO edge -> human readable approach of the intersection
EDGE_NAMES = {
    "E0": "West-Approach",
    "E1": "North-Approach",
    "E2": "East-Approach",
    "E3": "South-Approach",
    "-E0": "West-Exit",
    "-E1": "North-Exit",
    "-E2": "East-Exit",
    "-E3": "South-Exit",
}

SEVERITY_LEVELS = ["minor", "moderate", "severe", "critical"]


def road_name(lane_id: str) -> str:
    """Map a SUMO lane id such as ``E2_2`` or ``:J1_5_0`` to a readable road."""
    if not lane_id:
        return "J1-Intersection"
    if lane_id.startswith(":"):
        return "J1-Intersection"
    edge = lane_id.rsplit("_", 1)[0]
    return EDGE_NAMES.get(edge, edge)


def lane_index(lane_id: str) -> int:
    try:
        return int(lane_id.rsplit("_", 1)[1])
    except (IndexError, ValueError):
        return 0


def crash_message(*, sim_time: float, location, road: str, lane: int,
                  severity: str, involved, blocked: int, witness_count: int,
                  witness_speed: float, cause: str,
                  message_type: str = "EMERGENCY_HAZARD_WARNING",
                  rng: random.Random | None = None) -> dict:
    """Build m from the observed crash.  Returns a JSON-serialisable dict."""
    rng = rng or random.Random()
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.") + \
        f"{datetime.now(timezone.utc).microsecond // 1000:03d}Z"
    code = MESSAGE_TYPES.get(message_type, "HW")
    return {
        "Message Type": message_type,
        "Message ID": f"VANETs-{code}-{ts[:10].replace('-', '')}-"
                      f"{rng.randint(1, 999):03d}",
        "Timestamp": ts,
        "Location": {
            "latitude": round(location[1], 2),
            "longitude": round(location[0], 2),
            "road": road,
            "lane": lane,
        },
        "Event Details": {
            "cause": cause,
            "severity": severity,
            "sim_time_s": round(sim_time, 1),
            "involved": list(involved),
            "blocked": blocked,
            "witnesses": witness_count,
            "speed_kmh": round(witness_speed * 3.6, 1),
        },
    }


def serialize(message: dict) -> bytes:
    """Canonical byte encoding of m, used for hashing and for |m|."""
    return json.dumps(message, separators=(",", ":"),
                      sort_keys=True, ensure_ascii=False).encode("utf-8")


def new_sid(counter: int) -> bytes:
    """Unique session identifier (16 bytes): counter || timestamp || nonce."""
    return (counter.to_bytes(4, "big")
            + int(time.time_ns() // 1000).to_bytes(8, "big")[-8:]
            + secrets.token_bytes(4))


def format_message(message: dict, indent: int = 4) -> str:
    pad = " " * indent
    body = json.dumps(message, indent=2, ensure_ascii=False)
    return "\n".join(pad + line for line in body.splitlines())
