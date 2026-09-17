#!/usr/bin/env python3
"""不依赖 SUMO 的自检脚本。

用于在安装 SUMO 之前（或在没有图形界面的服务器上）确认：

    1. secp256r1 的实现正确（生成元阶、点运算、固定基预计算表）；
    2. DTT-ECDSA 四个协议自洽：掩码关系、聚合签名、公开验证（推论 1）；
    3. 严格穷举追踪能唯一还原出签名车辆集合；
    4. V2I 通信模型的时延随距离单调、在有效通信半径内可用；
    5. 消息 m 的五个字段齐全、可序列化。

    python3 selftest.py            # 默认 n=12, t=4
    python3 selftest.py --n 20 --t 5
"""

from __future__ import annotations

import argparse
import dataclasses
import math
import os
import random
import sys

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, BASE_DIR)

from dtt_ecdsa import curve, message as msg                      # noqa: E402
from dtt_ecdsa.console import setup_console, safe_print          # noqa: E402
from dtt_ecdsa.curve import (G, Q, is_on_curve, mul_G,           # noqa: E402
                             point_add, scalar_mul)
from dtt_ecdsa.entities import verify_signature                  # noqa: E402
from dtt_ecdsa.v2i import (V2XChannel, max_range_m, model_summary,  # noqa: E402
                           snr_db, select_mcs)
from dtt_ecdsa.vanet import (StaticLinkContext, VANETReportSession,  # noqa: E402
                             classify_severity, threshold_from_severity)

FAILED = []


def check(name: str, condition: bool, detail: str = ""):
    mark = "OK  " if condition else "FAIL"
    safe_print(f"  [{mark}] {name}" + (f"   {detail}" if detail else ""))
    if not condition:
        FAILED.append(name)


# --------------------------------------------------------------------------- #
def test_curve():
    safe_print("1. secp256r1")
    check("生成元在曲线上", is_on_curve(G))
    check("阶 q 正确（q·G = O）", mul_G(Q) is None)
    k = random.randrange(1, Q)
    check("固定基乘法 == 通用点乘", mul_G(k) == scalar_mul(k, G))
    a, b = random.randrange(1, Q), random.randrange(1, Q)
    check("标量乘法同态",
          point_add(mul_G(a), mul_G(b)) == mul_G((a + b) % Q))
    check("点在曲线上", is_on_curve(mul_G(a)))
    check("曲线名", curve.CURVE_NAME == "secp256r1", curve.CURVE_NAME)


def test_message():
    safe_print("2. 消息 m")
    m = msg.crash_message(
        sim_time=112.7, location=(5.0, -2.8), road="East-Approach", lane=2,
        severity="severe", involved=["v1", "v2"], blocked=22,
        witness_count=11, witness_speed=3.2,
        cause="red_light_running_collision", rng=random.Random(1))
    for field in ("Message Type", "Message ID", "Timestamp", "Location",
                  "Event Details"):
        check(f"字段 {field} 存在", field in m)
    raw = msg.serialize(m)
    check("可序列化", isinstance(raw, bytes) and len(raw) > 0,
          f"{len(raw)} 字节")
    check("序列化确定", msg.serialize(m) == raw)
    check("路名映射", msg.road_name("E2_2") == "East-Approach",
          msg.road_name("E2_2"))
    check("路口内部车道映射",
          msg.road_name(":J1_5_0") == "J1-Intersection",
          msg.road_name(":J1_5_0"))


def test_v2i():
    safe_print("3. V2I 通信模型")
    safe_print(f"       {model_summary()}")
    near, far = V2XChannel(), V2XChannel()
    near.wireless("V", "RSU", "test", 200, distance_m=10.0, neighbours=25)
    far.wireless("V", "RSU", "test", 200, distance_m=150.0, neighbours=25)
    check("时延随距离增加", far.total_ms > near.total_ms,
          f"10 m {near.total_ms:.3f} ms < 150 m {far.total_ms:.3f} ms")
    check("近距离选到高阶调制",
          select_mcs(snr_db(10.0))[0] > select_mcs(snr_db(150.0))[0],
          f"{select_mcs(snr_db(10.0))[0] / 1e6:.0f} Mbps vs "
          f"{select_mcs(snr_db(150.0))[0] / 1e6:.0f} Mbps")
    r = max_range_m()
    check("有效通信半径覆盖整个路口场景", r > 100.0, f"{r:.0f} m")
    out = V2XChannel()
    out.wireless("V", "RSU", "test", 200, distance_m=r + 100.0)
    check("超出通信半径的帧被丢弃",
          out.dropped == 1 and out.total_ms == 0.0)
    ch = V2XChannel()
    ch.wired("RSU", "TA", "test", 1000)
    check("有线回程时延为正", ch.total_ms > 0, f"{ch.total_ms:.3f} ms")


def test_severity():
    safe_print("4. TMC 门限策略")
    check("轻微", classify_severity(1, 0) == "minor")
    check("一般", classify_severity(2, 5) == "moderate")
    check("严重", classify_severity(3, 10) == "severe")
    check("特别严重", classify_severity(5, 40) == "critical")
    check("门限受候选数限制", threshold_from_severity("critical", 3) == 3)
    check("门限随严重程度递增",
          threshold_from_severity("minor", 99)
          < threshold_from_severity("critical", 99))


def test_scheme(n: int, t: int, seed: int):
    safe_print(f"5. DTT-ECDSA 四阶段流程  (n={n}, t={t})")
    rng = random.Random(seed)
    link = StaticLinkContext(
        distances={f"veh{i}": 20.0 + 4.0 * i for i in range(n)},
        neighbours=n)
    session = VANETReportSession(n=n, link=link, rng=rng)

    session.setup_authority()
    for i in range(n):
        session.register_vehicle(f"veh{i}", sim_time=float(i))
    check("n 辆车全部注册", len(session.registered) == n,
          f"{len(session.registered)}/{n}")
    check("注册后不再开放", not session.registration_open)
    check("车辆 ID 保留",
          [r.sumo_id for r in session.registered] == [f"veh{i}" for i in range(n)])
    t1 = session.finish_registration()
    check("阶段一有计算与通信时间", t1.compute_ms > 0 and t1.comm_ms > 0,
          t1.line())

    m = msg.crash_message(
        sim_time=120.0, location=(0.0, 0.0), road="East-Approach", lane=2,
        severity="severe", involved=["veh0", "veh1"], blocked=12,
        witness_count=n - 2, witness_speed=4.0,
        cause="red_light_running_collision", rng=rng)
    candidates = list(range(2, n))
    t2 = session.generate_signature(m, "severe", candidates, t=t)
    check("签名车辆数 == t", len(session.signer_indices) == t,
          str(session.ground_truth()))
    check("签名车辆取自候选集",
          set(session.signer_indices) <= set(candidates))
    check("阶段二有计算与通信时间", t2.compute_ms > 0 and t2.comm_ms > 0,
          t2.line())

    t3 = session.combine_signature()
    check("公开验证通过（推论 1）", session.verified)
    check("独立复验通过",
          verify_signature(session.sigma))
    check("阶段三有计算与通信时间", t3.compute_ms > 0 and t3.comm_ms > 0,
          t3.line())

    t4 = session.trace_signature()
    check("严格穷举搜索空间 == C(n,t)",
          session.trace_result.search_space == math.comb(n, t),
          f"C({n},{t}) = {math.comb(n, t):,}")
    check("追踪成功", session.trace_result.success)
    check("追踪结果 == 真实签名集合", session.trace_correct(),
          f"{session.ground_truth()} -> {session.traced_indices()}")
    check("阶段四有计算与通信时间", t4.compute_ms > 0 and t4.comm_ms > 0,
          t4.line())

    totals = session.phase_totals()
    check("三部分时间求和一致",
          abs(totals["init_ms"] + totals["sign_ms"] + totals["trace_ms"]
              - totals["total_ms"]) < 1e-6,
          f"初始化 {totals['init_ms']:.3f} + 签名 {totals['sign_ms']:.3f} + "
          f"追踪 {totals['trace_ms']:.3f} = {totals['total_ms']:.3f} ms")


def test_tamper(n: int, t: int, seed: int):
    """改一个比特，验证应当失败。"""
    safe_print("6. 负例：签名被篡改")
    rng = random.Random(seed + 1)
    link = StaticLinkContext(neighbours=n)
    session = VANETReportSession(n=n, link=link, rng=rng)
    session.setup_authority()
    for i in range(n):
        session.register_vehicle(f"veh{i}")
    session.finish_registration()
    m = msg.crash_message(
        sim_time=1.0, location=(0.0, 0.0), road="E", lane=1, severity="minor",
        involved=["veh0"], blocked=0, witness_count=n, witness_speed=1.0,
        cause="test", rng=rng)
    session.generate_signature(m, "minor", list(range(n)), t=t)
    session.combine_signature()
    good = session.sigma
    bad = dataclasses.replace(good, z=(good.z + 1) % Q)
    check("改动 z 后验证失败", not verify_signature(bad))


# --------------------------------------------------------------------------- #
def main(argv=None) -> int:
    setup_console()
    p = argparse.ArgumentParser(description="DTT-ECDSA 自检（不需要 SUMO）")
    p.add_argument("--n", type=int, default=12, help="注册车辆数")
    p.add_argument("--t", type=int, default=4, help="门限值")
    p.add_argument("--seed", type=int, default=2026, help="随机种子")
    args = p.parse_args(argv)
    if not 1 <= args.t <= args.n:
        safe_print("需要 1 <= t <= n")
        return 2

    random.seed(args.seed)
    safe_print("=" * 78)
    safe_print("DTT-ECDSA 自检（不依赖 SUMO）")
    safe_print("=" * 78)
    test_curve()
    test_message()
    test_v2i()
    test_severity()
    test_scheme(args.n, args.t, args.seed)
    test_tamper(args.n, args.t, args.seed)
    safe_print("=" * 78)
    if FAILED:
        safe_print(f"自检失败 {len(FAILED)} 项: {FAILED}")
        return 1
    safe_print("全部自检通过")
    return 0


if __name__ == "__main__":
    sys.exit(main())
