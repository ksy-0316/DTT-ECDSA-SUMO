#!/usr/bin/env python3
"""DTT-ECDSA + SUMO 批量测试脚本。

对固定的门限 t，遍历 n 取 [1.5t, 30] 中所有 %3 == 0 的值，每组无界面
（headless）跑 x 轮完整仿真，记录三部分时间：

    1. 初始化               —— TA 建立系统参数 + n 辆车注册 + 分发密钥
    2. 签名生成 + 签名聚合   —— 事故发生后 t 辆目击车协同签名并由 RSU 聚合
    3. 追踪                 —— Tracer 严格穷举 C(n,t) 还原签名车辆集合

三部分时间都包含实体之间的通信时延：车辆 <-> RSU 用基于 SUMO 实时距离的
IEEE 802.11p 模型，RSU <-> TA/TMC/Tracer 用有线回程模型。

每轮换一个随机种子，SUMO 的交通流与签名车辆的随机抽取都会随之改变。

结果写入 result/t=<t>.txt（每轮的追踪车辆集合与时间 + x 轮平均），同时写一份
result/t=<t>.json 便于后续画图。

用法：

    python3 run_batch.py --t 5 --x 10
    python3 run_batch.py            # 交互式询问 t 和 x
"""

from __future__ import annotations

import argparse
import math
import os
import statistics
import sys
import time
from datetime import datetime

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, BASE_DIR)

from dtt_ecdsa.console import setup_console, safe_print, pad   # noqa: E402
from sim.output import RunLogger, write_json              # noqa: E402
from sim.scenario import CrashScenario, ensure_sumo_tools  # noqa: E402

DEFAULT_CONFIG = os.path.join(BASE_DIR, "scenario", "crash_simu.sumocfg")
RESULT_DIR = os.path.join(BASE_DIR, "result")
LOG_DIR = os.path.join(RESULT_DIR, "logs")

N_MAX = 30
N_STEP = 3
RETRY_PER_ROUND = 3      # 一轮里最多换几次种子


def n_values(t: int) -> list[int]:
    """[1.5t, 30] 中所有能被 3 整除的 n。"""
    lo = math.ceil(1.5 * t)
    return [n for n in range(N_STEP, N_MAX + 1, N_STEP) if n >= lo and n >= t]


def parse_args(argv=None):
    p = argparse.ArgumentParser(
        description="SUMO + DTT-ECDSA 批量测试",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    p.add_argument("--t", type=int, default=None, help="门限值 t")
    p.add_argument("--x", type=int, default=None, help="每组重复轮数 x")
    p.add_argument("--config", default=DEFAULT_CONFIG, help="SUMO 配置文件")
    p.add_argument("--seed", type=int, default=1000, help="随机种子基值")
    p.add_argument("--steps", type=int, default=9000, help="每轮最大仿真步数")
    p.add_argument("--reg-start", type=float, default=95.0,
                   help="RSU 开放注册的时刻（秒）")
    p.add_argument("--crash-start", type=float, default=100.0,
                   help="开始挑选闯红灯车辆的时刻（秒）")
    p.add_argument("--result-dir", default=RESULT_DIR, help="结果目录")
    p.add_argument("--keep-logs", action="store_true",
                   help="保留每轮的仿真日志（默认只保留最后一轮）")
    return p.parse_args(argv)


def ask_int(prompt: str, low: int, high: int) -> int:
    while True:
        try:
            value = int(input(prompt).strip())
        except (ValueError, EOFError):
            safe_print("请输入一个整数")
            continue
        if low <= value <= high:
            return value
        safe_print(f"请输入 {low} ~ {high} 之间的整数")


# --------------------------------------------------------------------------- #
# 单轮仿真
# --------------------------------------------------------------------------- #
def run_round(config: str, n: int, t: int, seed: int, args,
              log_path: str) -> dict:
    """跑一轮完整仿真，返回这一轮的时间与追踪结果。"""
    log = RunLogger(os.path.dirname(log_path),
                    name=os.path.basename(log_path), quiet=True)
    scenario = CrashScenario(
        config=config, n=n, log=log, gui=False, t_override=t, seed=seed,
        reg_start=args.reg_start, crash_start=args.crash_start,
        stop_after_report=True)
    wall_start = time.perf_counter()
    scenario.start()
    ok = scenario.run(max_steps=args.steps)
    wall = (time.perf_counter() - wall_start) * 1000.0

    if not ok:
        return {"ok": False, "seed": seed, "reason": scenario.failure}

    session = scenario.session
    totals = session.phase_totals()
    return {
        "ok": True,
        "seed": seed,
        "n": n,
        "t": session.t,
        "init_ms": totals["init_ms"],
        "sign_ms": totals["sign_ms"],
        "trace_ms": totals["trace_ms"],
        "total_ms": totals["total_ms"],
        "wall_ms": wall,
        "traced": session.traced_indices(),
        "ground_truth": session.ground_truth(),
        "traced_sumo": [v[3] for v in session.identities()],
        "correct": session.trace_correct(),
        "verified": session.verified,
        "subsets_tested": session.trace_result.subsets_tested,
        "search_space": session.trace_result.search_space,
        "crash_time_s": scenario.crash.time,
        "severity": scenario.crash.severity,
        "candidates": len(scenario.crash.witness_candidates),
    }


def run_group(config: str, n: int, t: int, x: int, args) -> list[dict]:
    """同一组 (t, n) 重复 x 轮。"""
    rounds = []
    for r in range(1, x + 1):
        name = (f"n{n}_t{t}_r{r}.log" if args.keep_logs
                else f"n{n}_t{t}.log")
        log_path = os.path.join(LOG_DIR, name)
        result = None
        for attempt in range(RETRY_PER_ROUND):
            seed = args.seed + r * 97 + attempt * 7919 + n
            result = run_round(config, n, t, seed, args, log_path)
            if result["ok"]:
                break
            safe_print(f"      第 {r} 轮 seed={seed} 未完成上报"
                       f"（{result['reason']}），换种子重试")
        rounds.append(result)
        if result["ok"]:
            safe_print(f"      第 {r:2d}/{x} 轮: 初始化 {result['init_ms']:9.3f} ms | "
                       f"签名 {result['sign_ms']:8.3f} ms | "
                       f"追踪 {result['trace_ms']:9.3f} ms | "
                       f"追踪集合 {result['traced']} "
                       f"{'正确' if result['correct'] else '错误'}")
        else:
            safe_print(f"      第 {r:2d}/{x} 轮: 失败 —— {result['reason']}")
    return rounds


# --------------------------------------------------------------------------- #
# 结果输出
# --------------------------------------------------------------------------- #
def mean(values):
    return statistics.fmean(values) if values else 0.0


def group_summary(n: int, t: int, rounds: list[dict]) -> dict:
    ok = [r for r in rounds if r["ok"]]
    return {
        "n": n,
        "t": t,
        "rounds": len(rounds),
        "succeeded": len(ok),
        "traced_correct": sum(1 for r in ok if r["correct"]),
        "search_space": ok[0]["search_space"] if ok else math.comb(n, t),
        "avg_init_ms": mean([r["init_ms"] for r in ok]),
        "avg_sign_ms": mean([r["sign_ms"] for r in ok]),
        "avg_trace_ms": mean([r["trace_ms"] for r in ok]),
        "avg_total_ms": mean([r["total_ms"] for r in ok]),
        "avg_subsets": mean([r["subsets_tested"] for r in ok]),
        "avg_candidates": mean([r["candidates"] for r in ok]),
    }


def write_txt(path: str, t: int, x: int, groups: list[tuple[int, list, dict]]):
    sep = "=" * 100
    with open(path, "w", encoding="utf-8") as f:
        f.write(sep + "\n")
        f.write("SUMO + DTT-ECDSA 批量测试结果\n")
        f.write(sep + "\n")
        f.write(f"生成时间   : {datetime.now().isoformat(timespec='seconds')}\n")
        f.write(f"椭圆曲线   : secp256r1\n")
        f.write(f"门限 t     : {t}\n")
        f.write(f"每组轮数 x : {x}\n")
        f.write(f"n 取值     : {[g[0] for g in groups]}   "
                f"（[1.5t, 30] 中 %3==0 的数）\n")
        f.write("时间单位   : ms（保留 3 位小数，含实体间通信时延）\n")
        f.write("通信模型   : 车辆<->RSU 为基于 SUMO 实时距离的 IEEE 802.11p "
                "模型；RSU<->TA/TMC/Tracer 为有线回程\n")
        f.write(sep + "\n\n")

        for n, rounds, summary in groups:
            f.write("-" * 100 + "\n")
            f.write(f"n = {n}, t = {t}   严格穷举搜索空间 C({n},{t}) = "
                    f"{summary['search_space']:,}\n")
            f.write("-" * 100 + "\n")
            # 表头含中文，按显示宽度对齐（CJK 字符占两列）
            f.write(pad("轮次", 6) + pad("初始化(ms)", 14, ">")
                    + pad("签名生成+聚合(ms)", 20, ">")
                    + pad("追踪(ms)", 14, ">") + pad("合计(ms)", 14, ">")
                    + "   追踪车辆集合\n")
            for i, r in enumerate(rounds, 1):
                if not r["ok"]:
                    f.write(f"{i:<6}{'--':>14}{'--':>20}{'--':>14}{'--':>14}"
                            f"   失败: {r['reason']}\n")
                    continue
                f.write(f"{i:<6}{r['init_ms']:>14.3f}{r['sign_ms']:>20.3f}"
                        f"{r['trace_ms']:>14.3f}{r['total_ms']:>14.3f}"
                        f"   {r['traced']}"
                        f"{'' if r['correct'] else '  <-- 与真实集合不一致'}\n")
            f.write("\n")
            f.write(pad("平均", 6)
                    + f"{summary['avg_init_ms']:>14.3f}"
                    f"{summary['avg_sign_ms']:>20.3f}"
                    f"{summary['avg_trace_ms']:>14.3f}"
                    f"{summary['avg_total_ms']:>14.3f}\n")
            f.write(f"成功轮数 {summary['succeeded']}/{summary['rounds']}，"
                    f"追踪正确 {summary['traced_correct']}/"
                    f"{summary['succeeded']} 轮；"
                    f"平均检验子集 {summary['avg_subsets']:,.0f} 个，"
                    f"平均候选目击车辆 {summary['avg_candidates']:.1f} 辆\n\n")

            for i, r in enumerate(rounds, 1):
                if r["ok"]:
                    f.write(f"    第 {i} 轮追踪到的 SUMO 车辆: "
                            f"{r['traced_sumo']}\n")
            f.write("\n")

        f.write(sep + "\n")
        f.write("各组平均时间汇总\n")
        f.write(sep + "\n")
        f.write(f"{'n':>5}{'t':>5}" + pad("初始化(ms)", 16, ">")
                + pad("签名生成+聚合(ms)", 22, ">") + pad("追踪(ms)", 16, ">")
                + pad("合计(ms)", 16, ">") + "\n")
        for n, _, s in groups:
            f.write(f"{n:>5}{t:>5}{s['avg_init_ms']:>16.3f}"
                    f"{s['avg_sign_ms']:>22.3f}{s['avg_trace_ms']:>16.3f}"
                    f"{s['avg_total_ms']:>16.3f}\n")
        f.write(sep + "\n")


# --------------------------------------------------------------------------- #
def main(argv=None) -> int:
    setup_console()
    args = parse_args(argv)

    t = args.t if args.t is not None else ask_int("请输入门限 t: ", 1, N_MAX)
    x = args.x if args.x is not None else ask_int("请输入测试轮数 x: ", 1, 1000)
    if t > N_MAX:
        safe_print(f"t 不能大于 {N_MAX}")
        return 2

    ns = n_values(t)
    if not ns:
        safe_print(f"t={t} 时 [1.5t, {N_MAX}] 内没有 %3==0 的 n")
        return 2

    ensure_sumo_tools()
    os.makedirs(args.result_dir, exist_ok=True)
    os.makedirs(LOG_DIR, exist_ok=True)

    worst = math.comb(max(ns), t)
    safe_print("=" * 100)
    safe_print("SUMO + DTT-ECDSA 批量测试")
    safe_print("=" * 100)
    safe_print(f"门限 t = {t}，每组 {x} 轮，n 取 {ns}")
    safe_print(f"最大搜索空间 C({max(ns)},{t}) = {worst:,}"
               f"（严格穷举，约 3 us/子集，最坏 {worst * 3e-6:.1f} s/轮）")
    if worst > 5e7:
        safe_print("[提示] 搜索空间很大，整批测试会比较久")
    safe_print("")

    groups = []
    batch_start = time.perf_counter()
    for n in ns:
        safe_print(f"  === n = {n}, t = {t}  (C({n},{t}) = "
                   f"{math.comb(n, t):,}) ===")
        rounds = run_group(args.config, n, t, x, args)
        summary = group_summary(n, t, rounds)
        groups.append((n, rounds, summary))
        safe_print(f"      平均: 初始化 {summary['avg_init_ms']:9.3f} ms | "
                   f"签名 {summary['avg_sign_ms']:8.3f} ms | "
                   f"追踪 {summary['avg_trace_ms']:9.3f} ms | "
                   f"合计 {summary['avg_total_ms']:10.3f} ms")
        safe_print("")

    txt = os.path.join(args.result_dir, f"t={t}.txt")
    write_txt(txt, t, x, groups)
    js = write_json(args.result_dir, f"t={t}.json", {
        "generated_at": datetime.now().isoformat(timespec="seconds"),
        "curve": "secp256r1",
        "t": t, "x": x, "n_values": ns,
        "unit": "ms",
        "groups": [
            {"summary": s,
             "rounds": [r for r in rounds]}
            for _, rounds, s in groups
        ],
    })

    elapsed = time.perf_counter() - batch_start
    safe_print("=" * 100)
    safe_print(f"批量测试完成，用时 {elapsed:.1f} s")
    safe_print(f"结果文件: {txt}")
    safe_print(f"JSON    : {js}")
    safe_print(f"每轮日志: {LOG_DIR}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
