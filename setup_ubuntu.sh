#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# Ubuntu 上安装并验证 SUMO + DTT-ECDSA 仿真环境
#
#   chmod +x setup_ubuntu.sh
#   ./setup_ubuntu.sh
#
# 在 Ubuntu 20.04 / 22.04 / 24.04 上验证。除了 python3 之外不需要任何第三方
# python 库：椭圆曲线、哈希、通信模型都是标准库实现的。
# ---------------------------------------------------------------------------
set -euo pipefail

say() { printf '\n\033[1;36m==> %s\033[0m\n' "$*"; }
warn() { printf '\033[1;33m[!] %s\033[0m\n' "$*"; }

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# --------------------------------------------------------------------------- #
say "1/5 检查 python3"
if ! command -v python3 >/dev/null 2>&1; then
    sudo apt-get update
    sudo apt-get install -y python3
fi
python3 --version
PY_OK=$(python3 -c 'import sys; print(1 if sys.version_info >= (3, 9) else 0)')
if [ "$PY_OK" != "1" ]; then
    warn "需要 python3 >= 3.9（代码里用了 X | None 这种类型标注）"
    exit 1
fi

# --------------------------------------------------------------------------- #
say "2/5 安装 SUMO"
if command -v sumo >/dev/null 2>&1; then
    echo "已安装: $(sumo --version | head -n 1)"
else
    echo "从 Ubuntu 官方源安装 sumo / sumo-tools / sumo-doc"
    sudo apt-get update
    sudo apt-get install -y sumo sumo-tools sumo-doc
    # 官方源里的版本偏旧时，可改用 SUMO 官方 PPA：
    #   sudo add-apt-repository ppa:sumo/stable
    #   sudo apt-get update && sudo apt-get install -y sumo sumo-tools sumo-doc
    # 或者完全用 pip（不需要 root，但没有 sumo-gui）：
    #   python3 -m pip install --user eclipse-sumo traci sumolib
fi

# --------------------------------------------------------------------------- #
say "3/5 设置 SUMO_HOME"
if [ -z "${SUMO_HOME:-}" ]; then
    for candidate in /usr/share/sumo /usr/local/share/sumo /usr/lib/sumo; do
        if [ -d "$candidate/tools" ]; then
            export SUMO_HOME="$candidate"
            break
        fi
    done
fi

if [ -n "${SUMO_HOME:-}" ]; then
    echo "SUMO_HOME=$SUMO_HOME"
    if ! grep -q 'export SUMO_HOME=' "$HOME/.bashrc" 2>/dev/null; then
        echo "export SUMO_HOME=$SUMO_HOME" >> "$HOME/.bashrc"
        echo "已写入 ~/.bashrc（新开终端生效，当前终端请手动 source ~/.bashrc）"
    fi
else
    warn "没找到 SUMO_HOME；若是 pip 安装的 SUMO 可以忽略，traci 会自己解析"
fi

# --------------------------------------------------------------------------- #
say "4/5 检查 traci 是否可导入"
SUMO_HOME="${SUMO_HOME:-}" python3 - <<'PY'
import os
import sys

home = os.environ.get("SUMO_HOME")
if home:
    sys.path.append(os.path.join(home, "tools"))
try:
    import traci  # noqa: F401
    import sumolib  # noqa: F401
    print("traci / sumolib 导入成功")
except ImportError as exc:
    print(f"导入失败: {exc}")
    print("请执行: python3 -m pip install --user traci sumolib")
    sys.exit(1)
PY

# --------------------------------------------------------------------------- #
say "5/5 自检 + 一次完整仿真"
cd "$HERE"
python3 selftest.py
python3 run_simulation.py --n 12 --t 3 --seed 1 --stop-after-report

say "环境就绪"
cat <<'EOF'
常用命令：

    python3 run_simulation.py --n 20                 # 无界面跑一次完整场景
    python3 run_simulation.py --n 20 --gui           # 打开 SUMO GUI 观察
    python3 run_simulation.py --n 20 --t 5 --seed 7  # 指定门限与随机种子
    python3 run_batch.py --t 5 --x 10                # 批量测试，结果写 result/
    python3 selftest.py                              # 不需要 SUMO 的自检
EOF
