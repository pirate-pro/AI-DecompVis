# AI-DecompVis

AI-DecompVis 是面向新手与进阶分析者的 AI 反编译可视化平台。当前主线已进入 P4/P5（Advanced Decompiler Core）阶段，重点是把核心能力从“可用分析平台”推进到“更像真实 decompiler core”的 IR/SSA 驱动链路。

## Highlights (P4/P5)

- C++ core 仍是唯一分析真核心（无核心逻辑下沉到 Python/前端）
- 真实 PE x86/x64 输入链路可用（demo + 可分发真实样本）
- decoder abstraction 下的双后端策略：
  - 主路径：`native-byte-lift` image decode backend（真实文件级解码 + lifting）
  - 回退路径：`objdump-intel`/规则解码路径（兼容与诊断）
- 架构无关 IR + intraprocedural SSA + MemorySSA-like（MemoryDef/Use/Phi）已落地
- function summary 与 evidence/confidence 增强：支持 IR/SSA/stack/import/string 线索
- 基础复杂控制流信号：indirect control / switch-candidate / thunk/no-return hints
- 用户约束 -> 再分析闭环（已实现 `no_return`、`indirect_target`）
- runtime mode：embedded + daemon（gRPC，版本字段 + 取消链路）
- Web/Electron/VS Code 维持 thin client，共享同一后端契约

## Repository Layout

- `core/aidecomp_core`: C++20 analysis core
- `core/aidecomp_py`: pybind11 bridge
- `services/aidecomp_api`: FastAPI platform/orchestration
- `services/aidecompd`: local gRPC daemon
- `apps/web`: React + TypeScript + Vite
- `apps/desktop-electron`: Electron shell MVP
- `plugins/vscode`: VS Code thin plugin MVP
- `plugins/ida`, `plugins/ghidra`: adapter contract docs
- `shared/proto`: gRPC contracts
- `shared/schemas`: JSON schema
- `samples`: demo + real PE fixtures (含 switch 样本)
- `tests/golden`: golden corpus assertions

## Prerequisites

- Python 3.10+
- Node.js 20+
- `uv`
- `objdump`（可选，用于回退路径与诊断）

## Setup

```bash
uv venv .venv
UV_CACHE_DIR=/tmp/.uv-cache uv pip install --python .venv/bin/python -r requirements-dev.txt

scripts/build_core.sh

cd apps/web && npm install
cd ../desktop-electron && npm install
cd ../../plugins/vscode && npm install
cd ../..
```

## Run

### 0) One-command local stack (recommended)

```bash
scripts/run_dev_stack.sh
```

该脚本会自动处理端口占用，并把前端代理到同次启动的后端。

### 1) Embedded mode (default)

```bash
PYTHONPATH=core/aidecomp_py/python:services/aidecomp_api:services \
  .venv/bin/uvicorn aidecomp_api.main:app --app-dir services/aidecomp_api --host 127.0.0.1 --port 8000
```

### 2) Daemon mode

Start daemon:

```bash
PYTHONPATH=core/aidecomp_py/python:services/aidecomp_api:services \
  .venv/bin/python -m aidecompd.main
```

Start API in daemon mode:

```bash
AIDECOMP_RUNTIME_MODE=daemon AIDECOMPD_TARGET=127.0.0.1:50051 \
PYTHONPATH=core/aidecomp_py/python:services/aidecomp_api:services \
  .venv/bin/uvicorn aidecomp_api.main:app --app-dir services/aidecomp_api --host 127.0.0.1 --port 8000
```

### 3) Web

```bash
cd apps/web
npm run dev
```

如果后端不是 `8000`，可指定代理目标：

```bash
cd apps/web
VITE_PROXY_TARGET=http://127.0.0.1:8001 npm run dev
```

### 4) Desktop MVP

```bash
cd apps/desktop-electron
npm run dev
```

### 5) VS Code plugin MVP

```bash
cd plugins/vscode
npm run build
```

然后在 VS Code 打开 `plugins/vscode`，按 `F5` 启动 Extension Development Host。

## Tests

### C++ core

```bash
scripts/test_core.sh
```

### Python bridge + API + golden corpus

```bash
PYTHONPATH=core/aidecomp_py/python:services/aidecomp_api:services \
  .venv/bin/pytest tests/python tests/api -q
```

### Frontend

```bash
cd apps/web
npm run test
npm run build
```

### VS Code plugin build smoke

```bash
cd plugins/vscode
npm run build
```

## Current Supported Real Input Range

- 格式：PE/COFF 可执行文件（`.exe`）
- 架构：x86 / x64
- 输入方式：
  - 直接填写 `binary_path`
  - 工作区自动扫描候选程序（WSL 路径 + `/mnt/*` 挂载盘）并按优先级排序
- 样本：`real_pe_minimal_x64`、`real_pe_switch_x64`
- 解码后端现状：
  - `native-byte-lift` 为主路径（文件级 decode + lifting）
  - `objdump-intel`/规则解码为回退路径
- IR/SSA 现状：
  - instruction -> IR lifting（寄存器/常量/load/store/call/branch/ret/cast/cmp）
  - SSA 版本化 + 合流 phi
  - MemorySSA-like（MemoryDef/Use/Phi）
- type/ABI 恢复现状：
  - calling convention hints（x64/cdecl/stdcall/fastcall）
  - params/locals/stack slots hints
  - import/string 驱动的语义标签与说明增强
- switch/indirect-call/exception 现状：
  - jump-table/indirect control 有基础识别与显式低置信度标注
  - thunk/no-return 有基础识别与用户约束覆盖
  - exception/unwind 仅预留，暂无完整恢复

## Embedded vs Daemon

- Embedded：
  - `client -> FastAPI -> pybind11 -> C++ core`
  - 调试最直接、部署最简单
- Daemon：
  - `client -> FastAPI -> gRPC -> aidecompd -> pybind11 -> C++ core`
  - 更清晰运行时边界，便于多客户端复用
  - 支持协议版本字段与取消链路（当前为 cooperative/best-effort）

## Known Limitations

- 主解码后端依赖本机 `objdump` 文本输出，尚非完整机器码 lifting 引擎
- SSA/MemorySSA 目前以函数内（intraprocedural）为主，跨过程传播仍有限
- 类型恢复为启发式（hint 级），尚未形成完整数据流驱动类型系统
- switch/jump-table 与间接调用目标恢复仍有不完整场景，统一以低置信度/unsupported 标识
- 伪代码结构化仍偏保守，复杂不可约 CFG 可能退化为 goto/unsupported 表达

## Docs

- `docs/architecture.md`
- `docs/runtime-modes.md`
- `docs/plugin-strategy.md`
- `docs/analysis-pipeline.md`
- `docs/evidence-and-confidence.md`
- `docs/ir-and-ssa.md`
- `docs/type-recovery.md`
- `docs/complex-control-flow.md`
- `docs/user-guided-reanalysis.md`
- `docs/golden-corpus.md`
- `docs/vscode-plugin-workflow.md`
- `docs/user-guide.md`

## Safety

仅用于合法授权分析、教学、调试与程序理解；不提供攻击、绕过或利用链能力。
