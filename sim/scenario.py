"""The SUMO scenario: crossroads, red-light running, crash, traffic control.

The traffic logic is the one of the reference project (v5.0): after
``crash_start`` seconds the first vehicle queueing on the east left-turn lane
``E2_2`` is designated the red-light runner, it is forced into the junction
against a north/south through vehicle, and the directional traffic control that
follows blocks most movements.

What is new is that the DTT-ECDSA session runs alongside it: vehicles register
with the TA through the RSU as they drive into range, and the crash is reported
with an aggregated threshold signature that the Tracer then traces.
"""

from __future__ import annotations

import math
import os
import random
import sys

from dtt_ecdsa import message as msg
from dtt_ecdsa.vanet import (VANETReportSession, LinkContext, RSU_RANGE_M,
                             classify_severity, threshold_from_severity)


# --------------------------------------------------------------------------- #
# SUMO / TraCI bootstrap
# --------------------------------------------------------------------------- #
def ensure_sumo_tools():
    """Make ``traci`` importable.

    On Ubuntu the usual way is ``apt install sumo`` plus
    ``export SUMO_HOME=/usr/share/sumo``, which puts the Python bindings under
    ``$SUMO_HOME/tools``.  A ``pip install eclipse-sumo traci sumolib`` setup
    already has them on ``sys.path``, so that case is accepted as well.
    """
    home = os.environ.get("SUMO_HOME")
    if home and os.path.isdir(os.path.join(home, "tools")):
        tools = os.path.join(home, "tools")
        if tools not in sys.path:
            sys.path.append(tools)
        return
    for path in ("/usr/share/sumo/tools",
                 "/usr/local/share/sumo/tools",
                 "/opt/sumo/tools",
                 r"C:\Program Files (x86)\Eclipse\Sumo\tools",
                 r"C:\Program Files\Eclipse\Sumo\tools"):
        if os.path.isdir(path):
            sys.path.append(path)
            os.environ["SUMO_HOME"] = os.path.dirname(path)
            return
    try:
        import traci  # noqa: F401
        return
    except ImportError:
        pass
    raise RuntimeError(
        "找不到 SUMO 的 Python 接口。请先安装 SUMO 并设置环境变量：\n"
        "    sudo apt install sumo sumo-tools sumo-doc\n"
        "    export SUMO_HOME=/usr/share/sumo\n"
        "或者直接用 pip 安装： pip install eclipse-sumo traci sumolib")


# geometry of the reference network: one crossroads, J1 at the origin
JUNCTION = (0.0, 0.0)
RSU_POSITION = (0.0, 0.0)          # the RSU is mounted on the intersection
CONTEXT_RADIUS_M = 300.0           # covers the whole network

EAST_LEFT_LANE = "E2_2"
THROUGH_LANES = ("E3_1", "E1_1")
TL_ID = "J1"
EAST_LEFT_LINK_INDEX = 5

WITNESS_RADIUS_M = 80.0            # who can testify about the crash
JAM_RADIUS_M = 80.0

ALLOWED_ROUTES = (
    "route_north_to_south", "route_east_to_west", "route_west_to_north",
    "route_east_to_north", "route_south_to_east",
    "route_west_to_south", "route_north_to_west",
)
ALLOWED_RIGHT_TURN_LANES = ("E0_0", "E1_0", "E2_0", "E3_0")
ALLOWED_LANES = ("E1_1", "E2_1", "E0_2")
ALLOWED_INTERNAL = (":J1_0", ":J1_1", ":J1_3", ":J1_4", ":J1_6",
                    ":J1_9", ":J1_11")

COLOR_RED = (255, 0, 0, 255)          # red-light runner
COLOR_YELLOW = (255, 255, 0, 255)     # struck vehicles
COLOR_GREEN = (0, 255, 0, 255)        # signers of the report
COLOR_CYAN = (0, 200, 255, 255)       # registered, but not signing this round
COLOR_GREY = (128, 128, 128, 255)     # allowed through
COLOR_DARK = (64, 64, 64, 255)        # blocked by the traffic control


def distance(p, q) -> float:
    return math.hypot(p[0] - q[0], p[1] - q[1])


# --------------------------------------------------------------------------- #
# Crash record
# --------------------------------------------------------------------------- #
class CrashEvent:
    def __init__(self):
        self.occurred = False
        self.time = 0.0
        self.location = JUNCTION
        self.road = "J1-Intersection"
        self.lane = 0
        self.red_vehicle = None
        self.target_vehicle = None
        self.struck_vehicles: list[str] = []
        self.blocked = 0
        self.witness_candidates: list[str] = []
        self.severity = "unknown"
        self.description = ""

    def involved(self) -> list[str]:
        out = [self.red_vehicle] if self.red_vehicle else []
        return out + [v for v in self.struck_vehicles if v != self.red_vehicle]


# --------------------------------------------------------------------------- #
# Link context backed by the live simulation
# --------------------------------------------------------------------------- #
class SumoLinkContext(LinkContext):
    """Feeds the V2I model with the geometry SUMO reports each step."""

    def __init__(self, rsu_position=RSU_POSITION):
        self.rsu_position = rsu_position
        self.positions: dict[str, tuple] = {}
        self.speeds: dict[str, float] = {}
        self.lanes: dict[str, str] = {}
        self.last_seen_distance: dict[str, float] = {}

    def update(self, results: dict):
        """``results`` is one context-subscription snapshot."""
        import traci.constants as tc
        self.positions.clear()
        self.speeds.clear()
        self.lanes.clear()
        for vid, vals in results.items():
            pos = vals.get(tc.VAR_POSITION)
            if pos is None:
                continue
            self.positions[vid] = pos
            self.speeds[vid] = vals.get(tc.VAR_SPEED, 0.0)
            self.lanes[vid] = vals.get(tc.VAR_LANE_ID, "")
            self.last_seen_distance[vid] = distance(pos, self.rsu_position)

    # -- LinkContext ---------------------------------------------------- #
    def distance(self, sumo_id: str) -> float:
        pos = self.positions.get(sumo_id)
        if pos is not None:
            return distance(pos, self.rsu_position)
        # the vehicle has left the network: it stays registered, and the model
        # falls back to the last geometry actually observed for it
        return self.last_seen_distance.get(sumo_id, RSU_RANGE_M)

    def neighbour_count(self) -> int:
        return len(self.positions)

    # -- convenience ----------------------------------------------------- #
    def in_range(self, sumo_id: str) -> bool:
        pos = self.positions.get(sumo_id)
        return pos is not None and distance(pos, self.rsu_position) <= RSU_RANGE_M

    def speed(self, sumo_id: str) -> float:
        return self.speeds.get(sumo_id, 0.0)

    def lane(self, sumo_id: str) -> str:
        return self.lanes.get(sumo_id, "")


# --------------------------------------------------------------------------- #
# The scenario
# --------------------------------------------------------------------------- #
class CrashScenario:
    """Drives SUMO and the DTT-ECDSA session together."""

    def __init__(self, config: str, n: int, log, *, gui: bool = False,
                 t_override: int | None = None, seed: int | None = None,
                 step_length: float = 0.1, reg_start: float = 95.0,
                 crash_start: float = 100.0, report_delay: float = 5.0,
                 stop_after_report: bool = False, trail_steps: int = 300):
        self.config = config
        self.n = n
        self.log = log
        self.gui = gui
        self.t_override = t_override
        self.seed = seed
        self.step_length = step_length
        self.reg_start = reg_start
        self.crash_start = crash_start
        self.report_delay = report_delay
        self.stop_after_report = stop_after_report
        self.trail_steps = trail_steps

        self.rng = random.Random(seed)
        self.link = SumoLinkContext()
        self.session = VANETReportSession(n=n, link=self.link, rng=self.rng)
        self.crash = CrashEvent()

        self.step = 0
        self.sim_time = 0.0
        self.init_done = False
        self.crash_selected = False
        self.collision_armed = False
        self.crash_detected = False
        self.report_done = False
        self.threshold_source = ""
        self.failure = ""
        self._seen: set[str] = set()
        self._registration_open_logged = False
        self._crash_search_since = crash_start
        self._crash_search_logged = False
        self._red_entry_lane = EAST_LEFT_LANE
        self._report_attempt = 0.0
        self._phase_lines: list[str] = []

    # ------------------------------------------------------------------ #
    # SUMO lifecycle
    # ------------------------------------------------------------------ #
    def start(self):
        import traci
        import traci.constants as tc

        binary = "sumo-gui" if self.gui else "sumo"
        cmd = [binary, "-c", self.config,
               "--collision.check-junctions", "true",
               "--collision.action", "warn",
               "--collision.mingap-factor", "0",
               "--collision.stoptime", "9999",
               "--step-length", str(self.step_length),
               "--no-warnings", "true",
               "--no-step-log", "true",
               "--time-to-teleport", "-1"]
        if self.seed is not None:
            cmd += ["--seed", str(self.seed)]
        self.log(f"启动 SUMO: {' '.join(cmd)}")
        traci.start(cmd)
        traci.junction.subscribeContext(
            TL_ID, tc.CMD_GET_VEHICLE_VARIABLE, CONTEXT_RADIUS_M,
            [tc.VAR_POSITION, tc.VAR_SPEED, tc.VAR_LANE_ID, tc.VAR_ROUTE_ID])
        self._tc = tc
        self._traci = traci

    def close(self):
        try:
            self._traci.close()
        except Exception:
            pass

    # ------------------------------------------------------------------ #
    # Phase 1 -- progressive registration
    # ------------------------------------------------------------------ #
    #: vehicles admitted per simulation step.  The RSU announcement reaches
    #: everyone in range at once, but the replies contend for the channel, so
    #: they are spread over a few steps instead of arriving all at once.
    MAX_REG_PER_STEP = 2

    def _register_new_vehicles(self):
        """The first n vehicles the RSU sees in range join the scheme."""
        if not self.session.registration_open:
            return
        admitted = 0
        for vid in sorted(self.link.positions):
            if vid in self._seen or not self.link.in_range(vid):
                continue
            self._seen.add(vid)
            if self.session.register_vehicle(vid, self.sim_time):
                idx = len(self.session.registered) - 1
                self._set_color(vid, COLOR_CYAN)
                if idx == 0 or (idx + 1) % 5 == 0 or idx + 1 == self.n:
                    self.log(f"[注册] {idx + 1}/{self.n}  {vid} "
                             f"(d={self.link.distance(vid):5.1f} m)")
            if not self.session.registration_open:
                break
            admitted += 1
            if admitted >= self.MAX_REG_PER_STEP:
                break

    def _finish_registration(self):
        timing = self.session.finish_registration()
        self.init_done = True
        self.log("")
        self.log(f"系统初始化阶段已完成  ({self.n} 辆车完成注册)")
        self.log("    " + timing.line())
        self._phase_lines.append("[阶段1] 系统初始化阶段已完成")

    # ------------------------------------------------------------------ #
    # Crash choreography (ported from the reference scenario)
    # ------------------------------------------------------------------ #
    def _east_left_is_red(self) -> bool:
        try:
            state = self._traci.trafficlight.getRedYellowGreenState(TL_ID)
            if len(state) > EAST_LEFT_LINK_INDEX:
                return state[EAST_LEFT_LINK_INDEX] in ("r", "R")
        except Exception:
            pass
        return False

    def _pick_red_light_runner(self):
        try:
            on_lane = self._traci.lane.getLastStepVehicleIDs(EAST_LEFT_LANE)
        except Exception:
            return None
        waiting = []
        for vid in on_lane:
            pos = self.link.positions.get(vid)
            if pos is None:
                continue
            d = distance(pos, JUNCTION)
            if self.link.speed(vid) < 2.0 and d < 50.0:
                waiting.append((d, vid))
        if waiting:
            waiting.sort()
            return waiting[0][1]
        return on_lane[0] if on_lane else None

    # 目标车筛选条件：(最低速度, 距路口最近距离, 最远距离)
    # 强度逐级放宽，见 _pick_through_target
    THROUGH_TIERS = ((3.0, 12.0, 45.0), (1.0, 6.0, 60.0), (0.0, 0.0, 80.0))

    def _pick_through_target(self):
        """A north/south through vehicle for the red-light runner to hit.

        The preferred pick is a vehicle clearly under way and still a couple of
        seconds from the stop line.  The north/south approaches of this network
        are only 40 m long and stay congested for most of the light cycle, so
        the window is widened the longer no pair is found -- otherwise the
        crash is postponed by minutes and the registered vehicles have long
        since left the scene by the time the report is due.  The loosest tier
        compares with ``>=`` so that a queued (speed 0) vehicle still counts;
        ``_drive_into_junction`` overrides its speed anyway.
        """
        waited = self.sim_time - self._crash_search_since
        tier = 0 if waited < 6.0 else (1 if waited < 12.0 else 2)
        min_speed, lo, hi = self.THROUGH_TIERS[tier]

        candidates = []
        for lane in THROUGH_LANES:
            try:
                ids = self._traci.lane.getLastStepVehicleIDs(lane)
            except Exception:
                continue
            for vid in ids:
                pos = self.link.positions.get(vid)
                if pos is None:
                    continue
                d = distance(pos, JUNCTION)
                if self.link.speed(vid) >= min_speed and lo <= d <= hi:
                    candidates.append((d, vid))
        if candidates:
            candidates.sort()
            return candidates[0][1]
        return None

    def select_crash_vehicles(self) -> bool:
        red = self._pick_red_light_runner()
        target = self._pick_through_target()
        if not red or not target:
            return False
        self.crash.red_vehicle = red
        self.crash.target_vehicle = target
        self._red_entry_lane = self.link.lane(red) or EAST_LEFT_LANE
        self._set_color(red, COLOR_RED)
        self.log(f"事故车辆已选定: 闯红灯车 {red} (E2_2 左转道, "
                 f"{'红灯' if self._east_left_is_red() else '绿灯'}), "
                 f"直行车 {target}")
        self.crash_selected = True
        return True

    def _drive_into_junction(self):
        """Keep both vehicles converging on the junction centre."""
        traci = self._traci
        alive = traci.vehicle.getIDList()
        red, target = self.crash.red_vehicle, self.crash.target_vehicle
        for vid, profile in ((red, ((25, 18), (15, 15), (8, 13), (0, 12))),
                             (target, ((20, 14), (12, 12), (6, 11), (0, 10)))):
            if vid not in alive:
                continue
            try:
                traci.vehicle.setSpeedMode(vid, 0)
                traci.vehicle.setLaneChangeMode(vid, 0)
                d = distance(self.link.positions.get(vid, JUNCTION), JUNCTION)
                for threshold, speed in profile:
                    if d > threshold:
                        traci.vehicle.setSpeed(vid, speed)
                        break
            except Exception:
                continue
        self._synchronise(red, target, alive)

    def _synchronise(self, red, target, alive):
        """Nudge the speeds so both arrive at the centre at the same moment."""
        if red not in alive or target not in alive:
            return
        traci = self._traci
        p1 = self.link.positions.get(red)
        p2 = self.link.positions.get(target)
        if p1 is None or p2 is None:
            return
        d1, d2 = distance(p1, JUNCTION), distance(p2, JUNCTION)
        if d1 >= 40.0 or d2 >= 40.0:
            return
        s1, s2 = self.link.speed(red), self.link.speed(target)
        try:
            if s1 > 0.5 and s2 > 0.5:
                eta1, eta2 = d1 / s1, d2 / s2
                if eta1 > eta2 + 0.5:
                    traci.vehicle.setSpeed(red, min(20.0, s1 * 1.15))
                    traci.vehicle.setSpeed(target, max(6.0, s2 * 0.9))
                elif eta2 > eta1 + 0.5:
                    traci.vehicle.setSpeed(target, min(18.0, s2 * 1.15))
                    traci.vehicle.setSpeed(red, max(6.0, s1 * 0.9))
                if distance(p1, p2) < 15.0:
                    if s1 < 8.0:
                        traci.vehicle.setSpeed(red, 10.0)
                    if s2 < 8.0:
                        traci.vehicle.setSpeed(target, 10.0)
            else:
                if s1 < 5.0:
                    traci.vehicle.setSpeed(red, 12.0)
                if s2 < 5.0:
                    traci.vehicle.setSpeed(target, 10.0)
        except Exception:
            pass

    def _collision_happened(self) -> bool:
        red, target = self.crash.red_vehicle, self.crash.target_vehicle
        try:
            colliding = set(self._traci.simulation.getCollidingVehiclesIDList())
        except Exception:
            colliding = set()
        if red in colliding or target in colliding:
            return True
        p1 = self.link.positions.get(red)
        p2 = self.link.positions.get(target)
        if p1 is None or p2 is None:
            return False
        return (distance(p1, p2) < 8.0
                and distance(p1, JUNCTION) < 20.0
                and distance(p2, JUNCTION) < 20.0)

    def _struck_vehicles(self) -> list[str]:
        red = self.crash.red_vehicle
        p_red = self.link.positions.get(red)
        if p_red is None:
            return [self.crash.target_vehicle] if self.crash.target_vehicle else []
        try:
            colliding = set(self._traci.simulation.getCollidingVehiclesIDList())
        except Exception:
            colliding = set()
        struck = []
        for vid, pos in self.link.positions.items():
            if vid == red:
                continue
            if (vid in colliding and red in colliding) or (
                    distance(p_red, pos) < 8.0
                    and distance(p_red, JUNCTION) < 20.0
                    and distance(pos, JUNCTION) < 20.0):
                struck.append(vid)
        if not struck and self.crash.target_vehicle:
            struck = [self.crash.target_vehicle]
        return struck

    def handle_crash(self):
        crash = self.crash
        crash.occurred = True
        crash.time = self.sim_time
        p1 = self.link.positions.get(crash.red_vehicle, JUNCTION)
        p2 = self.link.positions.get(crash.target_vehicle, JUNCTION)
        crash.location = ((p1[0] + p2[0]) / 2.0, (p1[1] + p2[1]) / 2.0)
        lane_id = self.link.lane(crash.red_vehicle)
        if not lane_id or lane_id.startswith(":"):
            # inside the junction SUMO reports an internal lane; the approach
            # the red-light runner came from is the meaningful road name
            lane_id = self._red_entry_lane
        crash.road = msg.road_name(lane_id)
        crash.lane = msg.lane_index(lane_id)
        crash.struck_vehicles = self._struck_vehicles()
        for vid in crash.struck_vehicles:
            self._set_color(vid, COLOR_YELLOW)
        crash.description = (
            f"东向南左转车辆 {crash.red_vehicle} 闯红灯进入路口，"
            f"与 {len(crash.struck_vehicles)} 辆车相撞"
            f"({', '.join(crash.struck_vehicles)})，路口部分方向中断。")

        self.log("")
        self.log("!" * 78, stamp=False)
        self.log(f"检测到交通事故  位置 ({crash.location[0]:.2f}, "
                 f"{crash.location[1]:.2f})  道路 {crash.road} 车道 {crash.lane}")
        self.log(f"    涉事车辆: {crash.involved()}")
        self.log("!" * 78, stamp=False)

        self._freeze_crash_vehicles()
        crash.blocked = self._apply_traffic_control(verbose=True)
        crash.severity = classify_severity(len(crash.involved()), crash.blocked)
        self.crash_detected = True

    def _freeze_crash_vehicles(self):
        traci = self._traci
        alive = traci.vehicle.getIDList()
        for vid, color in ([(self.crash.red_vehicle, COLOR_RED)]
                           + [(v, COLOR_YELLOW) for v in self.crash.struck_vehicles]):
            if vid and vid in alive:
                try:
                    traci.vehicle.setSpeed(vid, 0)
                    traci.vehicle.setSpeedMode(vid, 0)
                    traci.vehicle.setColor(vid, color)
                except Exception:
                    pass

    def _movement_allowed(self, lane: str, route: str) -> bool:
        if route in ALLOWED_ROUTES:
            return True
        if lane in ALLOWED_RIGHT_TURN_LANES or lane in ALLOWED_LANES:
            return True
        if lane.startswith(":J1_"):
            base = lane.split("_0")[0] if "_0" in lane else lane
            return any(base.startswith(a) for a in ALLOWED_INTERNAL)
        return False

    def _apply_traffic_control(self, verbose: bool = False) -> int:
        """Directional control after the crash; returns how many are blocked."""
        traci = self._traci
        crashed = set(self.crash.involved())
        signers = set(self.signer_sumo_ids())
        blocked = allowed = 0
        try:
            vehicles = traci.vehicle.getIDList()
        except Exception:
            return 0
        for vid in vehicles:
            if vid in crashed or vid in signers:
                continue
            pos = self.link.positions.get(vid)
            if pos is None:
                continue
            try:
                lane = self.link.lane(vid)
                route = traci.vehicle.getRouteID(vid)
            except Exception:
                continue
            d = distance(pos, JUNCTION)
            try:
                if self._movement_allowed(lane, route):
                    traci.vehicle.setColor(vid, COLOR_GREY)
                    allowed += 1
                else:
                    traci.vehicle.setColor(vid, COLOR_DARK)
                    traci.vehicle.setSpeedMode(vid, 0)
                    if d < JAM_RADIUS_M:
                        blocked += 1
                        if d < 30.0:
                            traci.vehicle.setSpeed(vid, 0)
                        elif d < 50.0:
                            traci.vehicle.slowDown(vid, 0.5, 5.0)
                        else:
                            traci.vehicle.slowDown(vid, 2.0, 5.0)
            except Exception:
                continue
        if verbose:
            self.log(f"事故后交通管制: 放行 {allowed} 辆, 禁行 {blocked} 辆 "
                     f"({JAM_RADIUS_M:.0f} m 范围内)")
        return blocked

    # ------------------------------------------------------------------ #
    # Phases 2-4 -- the report
    # ------------------------------------------------------------------ #
    def witness_candidates(self) -> list[int]:
        """Registered vehicles still within 80 m of the crash: the witnesses.

        The returned values are *registry indices*, which is what the scheme
        works with.  The anonymity set stays the full n registered vehicles.
        """
        crashed = set(self.crash.involved())
        out = []
        for reg in self.session.registered:
            if reg.sumo_id in crashed:
                continue
            pos = self.link.positions.get(reg.sumo_id)
            if pos is None:
                continue
            if distance(pos, self.crash.location) <= WITNESS_RADIUS_M:
                out.append(reg.index)
        return out

    def signer_sumo_ids(self) -> list[str]:
        return [self.session.registered[i].sumo_id
                for i in self.session.signer_indices]

    def run_report(self) -> bool:
        """Protocols 2, 3 and 4, on the crash that just happened."""
        candidates = self.witness_candidates()
        self.crash.witness_candidates = [
            self.session.registered[i].sumo_id for i in candidates]

        severity = self.crash.severity
        if self.t_override is not None:
            t = min(self.t_override, self.session.n)
            self.threshold_source = f"命令行指定 t={t}"
        else:
            t = threshold_from_severity(severity, self.session.n)
            self.threshold_source = f"TMC 依据事故严重程度 '{severity}' 动态给出"

        if len(candidates) < t:
            self.log(f"目击车辆不足: 已注册且在事故点 {WITNESS_RADIUS_M:.0f} m 内的"
                     f"仅 {len(candidates)} 辆 < t={t}，等待更多车辆…")
            return False

        self.log("")
        self.log(f"TMC 门限决策: 严重程度 {severity} -> t = {t}   ({self.threshold_source})")
        self.log(f"候选目击车辆 {len(candidates)} 辆(已注册且在 "
                 f"{WITNESS_RADIUS_M:.0f} m 内)，从中随机抽取 {t} 辆签名")

        message = msg.crash_message(
            sim_time=self.crash.time,
            location=self.crash.location,
            road=self.crash.road,
            lane=self.crash.lane,
            severity=severity,
            involved=self.crash.involved(),
            blocked=self.crash.blocked,
            witness_count=len(candidates),
            witness_speed=self._mean_candidate_speed(candidates),
            cause="red_light_running_collision",
            rng=self.rng)

        t_sign = self.session.generate_signature(
            message, severity, candidates, t=t)
        for vid in self.signer_sumo_ids():
            self._set_color(vid, COLOR_GREEN)
        self.log("签名生成阶段已完成")
        self.log("    " + t_sign.line())
        self._phase_lines.append("[阶段2] 签名生成阶段已完成")

        t_comb = self.session.combine_signature()
        self.log("签名聚合阶段已完成")
        self.log("    " + t_comb.line())
        self.log(f"    公开验证 (推论 1): "
                 f"{'通过' if self.session.verified else '失败'}")
        self._phase_lines.append("[阶段3] 签名聚合阶段已完成")

        space = self.session.search_space()
        self.log(f"追踪开始: 严格穷举 C({self.session.n},{self.session.t}) "
                 f"= {space:,} 个候选子集")
        t_trace = self.session.trace_signature()
        self.log("签名追踪阶段已完成")
        self.log("    " + t_trace.line())
        self._phase_lines.append("[阶段4] 签名追踪阶段已完成")

        self.report_done = True
        return True

    def _mean_candidate_speed(self, candidates) -> float:
        speeds = [self.link.speed(self.session.registered[i].sumo_id)
                  for i in candidates]
        return sum(speeds) / len(speeds) if speeds else 0.0

    # ------------------------------------------------------------------ #
    # Main loop
    # ------------------------------------------------------------------ #
    def _set_color(self, vid, color):
        try:
            self._traci.vehicle.setColor(vid, color)
        except Exception:
            pass

    def run(self, max_steps: int = 9000) -> bool:
        traci = self._traci
        self.session.setup_authority()
        finished_at = None

        try:
            while self.step < max_steps:
                traci.simulationStep()
                self.step += 1
                self.sim_time = self.step * self.step_length
                self.log.sim_time = self.sim_time
                self.link.update(
                    traci.junction.getContextSubscriptionResults(TL_ID) or {})

                # -- phase 1 ------------------------------------------- #
                if not self.init_done and self.sim_time >= self.reg_start:
                    if not self._registration_open_logged:
                        self._registration_open_logged = True
                        self.log(f"RSU 开放注册服务，通信半径 "
                                 f"{RSU_RANGE_M:.0f} m，登记前 {self.n} 辆车")
                    self._register_new_vehicles()
                    if len(self.session.registered) >= self.n:
                        self._finish_registration()

                # -- crash choreography --------------------------------- #
                # The accident is only staged once initialisation is done:
                # the protocol order demands it, and a crash that fires while
                # vehicles are still registering would leave most of the
                # anonymity set far from the scene by report time.
                if (self.init_done and not self.crash_selected
                        and self.sim_time >= self.crash_start):
                    if not self._crash_search_logged:
                        self._crash_search_logged = True
                        self._crash_search_since = self.sim_time
                        self.log("开始挑选事故车辆（闯红灯车 + 南北直行车）")
                    self.select_crash_vehicles()
                if self.crash_selected and not self.crash_detected:
                    self._drive_into_junction()
                    if not self.collision_armed:
                        self.collision_armed = True
                    if self._collision_happened():
                        self.handle_crash()

                # -- phases 2..4 ---------------------------------------- #
                if self.crash_detected and not self.report_done:
                    self._freeze_crash_vehicles()
                    if self.step % 10 == 0:
                        self._apply_traffic_control()
                    # initialisation is guaranteed complete here (the crash is
                    # only staged after it), so go straight to the report
                    if (self.sim_time >= self.crash.time + self.report_delay
                            and self.sim_time - self._report_attempt >= 3.0):
                        self._report_attempt = self.sim_time
                        self.run_report()

                if self.report_done:
                    if finished_at is None:
                        finished_at = self.step
                        if self.stop_after_report:
                            break
                    self._freeze_crash_vehicles()
                    if self.step % 10 == 0:
                        self._apply_traffic_control()
                    if self.step - finished_at >= self.trail_steps:
                        break

                if self.step % 500 == 0:
                    self.log(f"仿真进行中: 车辆 {len(self.link.positions)} 辆, "
                             f"注册 {len(self.session.registered)}/{self.n}, "
                             f"状态 {self._status()}")
        except KeyboardInterrupt:
            self.log("用户中断仿真")
        finally:
            self.close()

        if not self.report_done and not self.failure:
            if not self.init_done:
                self.failure = (f"仿真结束前初始化未完成 "
                                f"({len(self.session.registered)}/{self.n})")
            elif not self.crash_detected:
                self.failure = "仿真结束前未发生碰撞"
            else:
                self.failure = "仿真结束前目击车辆始终不足，未能完成上报"
        return self.report_done

    def _status(self) -> str:
        if self.report_done:
            return "上报完成"
        if self.crash_detected:
            return "事故后-交通管制"
        if self.crash_selected:
            return "事故车辆已选定"
        if self.init_done:
            return "初始化完成, 等待事故"
        return "初始化(注册)中"

    def phase_lines(self) -> list[str]:
        return list(self._phase_lines)
