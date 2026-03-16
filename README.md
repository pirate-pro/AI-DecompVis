# AI-DecompVis

AI-DecompVis 是面向新手的 AI 反编译可视化平台。当前版本已从 P0 演示版推进到 P1/P2 合并阶段，支持真实 PE 输入链路与多入口（Web/Desktop/Plugin）演进。

## Highlights

- 真实输入：PE32/PE32+（x86/x64）最小可运行链路
- 核心分析仍由 C++ core 唯一承担
- runtime mode：embedded + daemon(gRPC)
- SQLite 本地工作区持久化
- Web 四区联动 + Program Summary + Progress + Workspace
- Electron Desktop MVP
- VS Code 插件 MVP（thin client）

## Repository Layout

- `core/aidecomp_core`: C++20 analysis core
- `core/aidecomp_py`: pybind11 bridge
- `services/aidecomp_api`: FastAPI platform/orchestration layer
- `services/aidecompd`: local gRPC daemon MVP
- `apps/web`: React + TypeScript + Vite
- `apps/desktop-electron`: Electron shell MVP
- `plugins/vscode`: VS Code extension MVP
- `plugins/ida`, `plugins/ghidra`: documented adapter contracts
- `shared/proto`: gRPC contracts
- `shared/schemas`: JSON schema
- `samples`: demo + real PE fixtures

## Prerequisites

- Python 3.10+
- Node.js 20+
- `uv`

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

### Python bridge + API

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

## Supported Real Input Range (current)

- 文件格式：PE/COFF executable (`.exe`) / basic PE images
- 架构：x86 / x64
- 已覆盖能力：
  - DOS/NT headers
  - section summary
  - entry point
  - imports/exports basic parse
  - executable section decode (subset opcode backend)
  - entry + call-target 函数发现
  - CFG/stack/calling convention/path summary
  - strings (ASCII/UTF16LE) extraction

## Known Limitations

- x86/x64 decoder backend 为教学型子集指令，不是全指令集
- import-aware 调用语义在间接调用场景下仍有限
- 伪代码结构化为启发式，不等同完整反编译器
- daemon 当前为本机单用户 MVP（无鉴权/多租户）
- desktop/plugin 仍是 MVP，重点在接入链路而非完整产品化

## Docs

- `docs/architecture.md`
- `docs/runtime-modes.md`
- `docs/plugin-strategy.md`

## Safety

仅用于合法授权分析、教学、调试与程序理解；不提供攻击、绕过或利用链能力。
