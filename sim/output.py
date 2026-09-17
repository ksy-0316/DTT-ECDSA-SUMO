"""Logging and result files for the SUMO DTT-ECDSA run."""

from __future__ import annotations

import json
import os
from datetime import datetime

from dtt_ecdsa.console import safe_print


class RunLogger:
    """Console + file logger stamped with the simulation clock."""

    def __init__(self, output_dir: str, name: str = "simulation_log.txt",
                 quiet: bool = False):
        self.output_dir = output_dir
        os.makedirs(output_dir, exist_ok=True)
        self.path = os.path.join(output_dir, name)
        self.quiet = quiet
        self.sim_time = 0.0
        with open(self.path, "w", encoding="utf-8") as f:
            f.write("SUMO + DTT-ECDSA 车祸上报仿真日志\n")
            f.write(f"开始时间: {datetime.now().isoformat()}\n")
            f.write("=" * 78 + "\n\n")

    def __call__(self, text: str = "", stamp: bool = True):
        line = f"[{self.sim_time:7.1f}s] {text}" if stamp else text
        if not self.quiet:
            safe_print(line)
        with open(self.path, "a", encoding="utf-8") as f:
            f.write(line + "\n")

    def banner(self, title: str):
        self("=" * 78, stamp=False)
        self(title, stamp=False)
        self("=" * 78, stamp=False)


def write_json(output_dir: str, name: str, payload: dict) -> str:
    os.makedirs(output_dir, exist_ok=True)
    path = os.path.join(output_dir, name)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2, ensure_ascii=False)
    return path


def crash_report(scenario, session) -> dict:
    """Everything about the accident and the signature that reported it."""
    crash = scenario.crash
    traced = session.identities()
    return {
        "generated_at": datetime.now().isoformat(),
        "scenario": {
            "sim_time_s": crash.time,
            "location": list(crash.location),
            "road": crash.road,
            "lane": crash.lane,
            "severity": crash.severity,
            "red_light_runner": crash.red_vehicle,
            "struck_vehicles": crash.struck_vehicles,
            "vehicles_involved": crash.involved(),
            "blocked_vehicles": crash.blocked,
            "witness_candidates": crash.witness_candidates,
            "description": crash.description,
        },
        "scheme": {
            "curve": "secp256r1",
            "n_registered": session.n,
            "t_threshold": session.t,
            "threshold_source": scenario.threshold_source,
            "search_space_C_n_t": session.search_space(),
            "signature_verified": session.verified,
        },
        "message": session.message,
        "signature": {
            "sid": session.sid.hex(),
            "R": [hex(session.sigma.R[0]), hex(session.sigma.R[1])],
            "Vp": [hex(session.sigma.Vp[0]), hex(session.sigma.Vp[1])],
            "z": hex(session.sigma.z),
            "bytes": session.sigma.wire_bytes(),
        },
        "tracing": {
            "success": session.trace_result.success,
            "correct": session.trace_correct(),
            "subsets_tested": session.trace_result.subsets_tested,
            "search_space": session.trace_result.search_space,
            "traced_indices": session.traced_indices(),
            "ground_truth_indices": session.ground_truth(),
            "traced_vehicles": [
                {"index": i, "vid": vid, "plate": plate, "sumo_id": sid}
                for i, vid, plate, sid in traced
            ],
        },
    }


def timing_report(session) -> dict:
    """The three end-to-end timings, plus the per-link breakdown."""
    out = {"unit": "ms", "phases": {}}
    for key, ph in session.timing.items():
        out["phases"][key] = {
            "name": ph.name,
            "compute_ms": round(ph.compute_ms, 3),
            "comm_ms": round(ph.comm_ms, 3),
            "total_ms": round(ph.total_ms, 3),
            "bytes": ph.channel.total_bytes,
            "links": [
                {"src": r.src, "dst": r.dst, "label": r.label, "kind": r.kind,
                 "bytes": r.nbytes, "count": r.count, "ms": round(r.ms, 3),
                 "distance_m": round(r.distance_m, 1),
                 "rate_mbps": round(r.rate_mbps, 1),
                 "snr_db": round(r.snr_db, 1)}
                for r in ph.channel.log
            ],
        }
    totals = session.phase_totals()
    out["totals"] = {k: round(v, 3) for k, v in totals.items()}
    return out
