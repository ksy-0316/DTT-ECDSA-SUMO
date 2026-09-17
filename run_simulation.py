#!/usr/bin/env python3
"""DTT-ECDSA 在 SUMO 上的车祸上报仿真 —— 主程序。

场景（沿用参考项目 v5.0 的交通逻辑）：

    0  ~  95 s   十字路口四个方向正常通行
   95 s 起       RSU 开放注册，随后驶入通信范围的前 n 辆车依次完成注册（阶段一）
  100 s 起       东进口左转道 E2_2 上等红灯的第一辆车被选为闯红灯车（红色）
                 该车冲入路口，与南北直行车相撞（被撞车标黄）
   碰撞后        分方向交通管制；事故点 80 m 内且已注册的车辆成为候选目击者
                 TMC 依据事故严重程度给出门限 t，随机抽 t 辆签名（绿色）
                 RSU 聚合签名（阶段二、三），Tracer 严格穷举追踪（阶段四）

用法：

    python3 run_simulation.py --n 20                # 无界面
    python3 run_simulation.py --n 20 --gui          # SUMO GUI
    python3 run_simulation.py --n 20 --t 4 --seed 7 # 指定门限与随机种子
"""

from __future__ import annotations

import argparse
import math
import os
import sys

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, BASE_DIR)

from dtt_ecdsa.console import setup_console, safe_print, pad  # noqa: E402
from dtt_ecdsa import message as msg                          # noqa: E402
from dtt_ecdsa.v2i import model_summary                       # noqa: E402
from dtt_ecdsa.vanet import RSU_RANGE_M, SEVERITY_THRESHOLD   # noqa: E402
from sim.output import (RunLogger, write_json, crash_report,  # noqa: E402
                        timing_report)
from sim.scenario import (CrashScenario, ensure_sumo_tools,   # noqa: E402
                          WITNESS_RADIUS_M)

DEFAULT_CONFIG = os.path.join(BASE_DIR, "scenario", "crash_simu.sumocfg")
DEFAULT_OUTPUT = os.path.join(BASE_DIR, "vanet_output")


def parse_args(argv=None):
    p = argparse.ArgumentParser(
        description="SUMO + DTT-ECDSA 车祸上报仿真",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    p.add_argument("--n", type=int, default=20,
                   help="初始化阶段注册的车辆数（匿名集合大小）")
    p.add_argument("--t", type=int, default=None,
                   help="门限值；不给则由 TMC 按事故严重程度动态决定")
    p.add_argument("--gui", action="store_true", help="使用 sumo-gui")
    p.add_argument("--config", default=DEFAULT_CONFIG, help="SUMO 配置文件")
    p.add_argument("--steps", type=int, default=9000,
                   help="最大仿真步数（步长 0.1 s，9000 步 = 900 s）")
    p.add_argument("--seed", type=int, default=None, help="随机种子")
    p.add_argument("--reg-start", type=float, default=95.0,
                   help="RSU 开放注册的时刻（秒）")
    p.add_argument("--crash-start", type=float, default=100.0,
                   help="开始挑选闯红灯车辆的时刻（秒）")
    p.add_argument("--output", default=DEFAULT_OUTPUT, help="输出目录")
    p.add_argument("--stop-after-report", action="store_true",
                   help="上报完成后立即结束仿真（批量测试用）")
    p.add_argument("--quiet", action="store_true", help="只写日志文件，不打印")
    return p.parse_args(argv)


def check_search_space(n: int, t: int | None, log):
    """严格穷举的代价随 C(n,t) 增长，事先提醒一次。"""
    t_max = t if t is not None else max(SEVERITY_THRESHOLD.values())
    t_max = min(t_max, n)
    space = math.comb(n, t_max)
    log(f"追踪搜索空间上界 C({n},{t_max}) = {space:,} "
        f"（严格穷举，约 3 us/子集，最坏 {space * 3e-6:.1f} s）")
    if space > 5e7:
        log("[提示] 搜索空间很大，建议减小 --n 或指定较小的 --t")


def print_result(scenario, session, log):
    """四个阶段的完成提示与追踪结果。"""
    log("")
    log("=" * 78, stamp=False)
    log("阶段完成情况", stamp=False)
    log("=" * 78, stamp=False)
    for line in scenario.phase_lines():
        log(line, stamp=False)

    log("")
    log("=" * 78, stamp=False)
    log("追踪结果", stamp=False)
    log("=" * 78, stamp=False)
    tr = session.trace_result
    log(f"注册车辆数 n        : {session.n}", stamp=False)
    log(f"门限值     t        : {session.t}   ({scenario.threshold_source})",
        stamp=False)
    log(f"事故严重程度        : {scenario.crash.severity}", stamp=False)
    log(f"候选目击车辆        : {len(scenario.crash.witness_candidates)} 辆"
        f"（已注册且在事故点 {WITNESS_RADIUS_M:.0f} m 内）", stamp=False)
    log(f"搜索空间 C(n,t)     : {tr.search_space:,}", stamp=False)
    log(f"实际检验子集数      : {tr.subsets_tested:,}", stamp=False)
    log(f"签名公开验证        : {'通过' if session.verified else '失败'}",
        stamp=False)
    log(f"追踪是否成功        : {'成功' if tr.success else '失败'}", stamp=False)
    log(f"真实签名车辆集合    : {session.ground_truth()}", stamp=False)
    log(f"追踪还原车辆集合    : {session.traced_indices()}", stamp=False)
    log(f"追踪结果是否正确    : "
        f"{'正确' if session.trace_correct() else '不正确'}", stamp=False)
    log("", stamp=False)
    log("追踪出的签名车辆明细：", stamp=False)
    # 车牌含中文，按显示宽度对齐
    log("    " + pad("索引", 6) + pad("车辆ID", 12) + pad("车牌", 12)
        + pad("SUMO车辆", 30) + pad("距RSU(m)", 10, ">"), stamp=False)
    for i, vid, plate, sumo_id in session.identities():
        d = session.registered[i].distance_m
        log("    " + pad(str(i), 6) + pad(vid, 12) + pad(plate, 12)
            + pad(sumo_id, 30) + f"{d:>10.1f}", stamp=False)

    log("")
    log("=" * 78, stamp=False)
    log("时间统计（计算 + 实体间通信，单位 ms）", stamp=False)
    log("=" * 78, stamp=False)
    log(f"通信模型: {model_summary()}", stamp=False)
    for key in ("init", "sign", "combine", "trace"):
        ph = session.timing.get(key)
        if ph:
            log(f"    {ph.line()}", stamp=False)
    totals = session.phase_totals()
    log("", stamp=False)
    log(f"    初始化                : {totals['init_ms']:10.3f} ms", stamp=False)
    log(f"    签名生成 + 签名聚合   : {totals['sign_ms']:10.3f} ms", stamp=False)
    log(f"    追踪                  : {totals['trace_ms']:10.3f} ms", stamp=False)
    log(f"    合计                  : {totals['total_ms']:10.3f} ms", stamp=False)

    log("")
    log("上报的消息 m：", stamp=False)
    log(msg.format_message(session.message), stamp=False)


def main(argv=None) -> int:
    setup_console()
    args = parse_args(argv)
    if args.n < 1:
        safe_print("n 必须 >= 1")
        return 2
    if args.t is not None and args.t < 1:
        safe_print("t 必须 >= 1")
        return 2
    if args.t is not None and args.t > args.n:
        safe_print(f"t={args.t} 不能大于 n={args.n}")
        return 2

    ensure_sumo_tools()
    os.makedirs(args.output, exist_ok=True)
    log = RunLogger(args.output, quiet=args.quiet)

    log.banner("SUMO + DTT-ECDSA  车祸数据上报仿真")
    log(f"场景配置: {args.config}", stamp=False)
    log(f"注册车辆数 n = {args.n}，门限 t = "
        f"{args.t if args.t is not None else 'TMC 动态决定'}", stamp=False)
    log(f"RSU 位于路口中心，通信半径 {RSU_RANGE_M:.0f} m；"
        f"注册开放于 {args.reg_start:.0f} s，事故选车于 {args.crash_start:.0f} s",
        stamp=False)
    log(f"通信模型: {model_summary()}", stamp=False)
    check_search_space(args.n, args.t, log)
    log("", stamp=False)

    scenario = CrashScenario(
        config=args.config, n=args.n, log=log, gui=args.gui,
        t_override=args.t, seed=args.seed,
        reg_start=args.reg_start, crash_start=args.crash_start,
        stop_after_report=args.stop_after_report)
    scenario.start()
    ok = scenario.run(max_steps=args.steps)

    if not ok:
        log("")
        log(f"仿真结束，但未能完成上报：{scenario.failure}", stamp=False)
        return 1

    session = scenario.session
    print_result(scenario, session, log)

    p1 = write_json(args.output, "crash_report.json",
                    crash_report(scenario, session))
    p2 = write_json(args.output, "timing_report.json", timing_report(session))
    log("")
    log(f"事故上报结果: {p1}", stamp=False)
    log(f"时间统计报告: {p2}", stamp=False)
    log(f"仿真日志    : {log.path}", stamp=False)
    return 0 if session.trace_correct() else 1


if __name__ == "__main__":
    sys.exit(main())
