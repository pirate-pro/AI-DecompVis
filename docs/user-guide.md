# AI-DecompVis 使用说明（中文）

本文档面向日常使用者，覆盖启动方式、核心工作流、可用功能与限制说明。

## 1. 系统是什么

AI-DecompVis 是一个“分析核心在 C++、平台在 FastAPI、界面在 Web/Desktop/Plugin”的反编译可视化系统，目标是帮助你理解：

- 程序控制流如何走（CFG）
- 栈和变量如何变化（stack/frame/slots）
- 为什么会得出某个解释（evidence + confidence）
- 在不确定场景下如何通过约束触发再分析（user-guided reanalysis）

## 2. 快速启动

### 2.1 首次安装

```bash
uv venv .venv
UV_CACHE_DIR=/tmp/.uv-cache uv pip install --python .venv/bin/python -r requirements-dev.txt
scripts/build_core.sh
cd apps/web && npm install
cd ../desktop-electron && npm install
cd ../../plugins/vscode && npm install
cd ../..
```

### 2.2 一键启动前后端（推荐）

```bash
scripts/run_dev_stack.sh
```

脚本行为：

- 自动选择空闲端口（避免 8000/5173 被占用时启动失败）
- 自动把前端代理到本次启动的后端端口
- `Ctrl+C` 时同时关闭前后端

### 2.3 手动分开启动

后端（embedded）：

```bash
scripts/run_api_embedded.sh
```

前端：

```bash
cd apps/web
npm run dev
```

## 3. 典型使用流程（Web）

### 步骤 1：进入工作区页

进入 `#/workspace` 页面：

- 选择已有项目，或创建新项目
- 选择样本（demo 或真实 PE）
- 使用“自动扫描可反编译程序”列表快速挑选 `exe/dll`
- 发起分析任务并观察进度

### 步骤 2：分析页联动查看

进入 `#/analysis` 页面，可完成：

- 函数列表筛选（函数名 / import / string / section）
- 选择函数后查看单函数 CFG
- 点击 block 联动汇编与伪代码高亮
- 点击指令查看 stack effect、寄存器和元信息
- 查看 Program Summary（sections/imports/strings/functions/entry）

### 步骤 3：解释页追溯证据

进入 `#/explain` 页面，可查看：

- instruction / block / function / path 四层 explanation
- evidence 列表（可回跳到 block / instruction）
- confidence 与 low-confidence/unsupported 提示

### 步骤 4：写入用户知识并再分析

可通过 API 或插件提交约束（如 `no_return` / `value_range` / `type_override` / `this_pointer`），触发再分析，观察：

- CFG/伪代码变化
- xref/call 关系变化
- explanation 与 confidence 变化

## 4. 当前可用功能

### 分析核心（C++）

- 真实 PE 输入（x86/x64）
- 解码抽象 + 主路径 native byte/image backend + fallback
- Program/Function/BasicBlock/Instruction 模型
- CFG / xref / call graph 基础恢复
- stack effect / frame / balance
- architecture-independent IR
- intraprocedural SSA + MemorySSA-like
- function summary + evidence/confidence
- 基础 jump-table/indirect/thunk/no-return hints
- 基础 unwind metadata 摘要（x64 样本）

### 平台层（FastAPI）

- embedded / daemon 双模式
- workspace/project/session + SQLite 持久化
- annotation / rename / bookmark
- explanation provider（rule-based + provider interface）
- SSE 任务进度 + 任务取消接口

### 客户端

- Web：中文界面 + 多页面（workspace/analysis/explain）
- Desktop（Electron MVP）：复用 Web 能力
- VS Code 插件（thin client MVP）：函数列表、解释查看、约束提交与刷新

## 5. 运行模式说明

### Embedded mode

- 路径：`Client -> FastAPI -> pybind11 -> C++ core`
- 优点：部署最简单、调试方便

### Daemon mode

- 路径：`Client -> FastAPI -> gRPC -> aidecompd -> pybind11 -> C++ core`
- 优点：边界清晰，便于多客户端复用同一核心

## 6. 测试与校验

核心测试：

```bash
scripts/test_core.sh
```

Python/API/golden：

```bash
PYTHONPATH=core/aidecomp_py/python:services/aidecomp_api:services \
  .venv/bin/pytest tests -q
```

前端：

```bash
cd apps/web
npm test
npm run build
```

插件：

```bash
cd plugins/vscode
npm run build
```

## 7. 已知限制（当前阶段）

- 仍属于工业化推进阶段，不是“源码级完美反编译器”
- 部分复杂间接控制流仍以低置信度或 unsupported 输出
- SSA/MemorySSA 目前以函数内为主，跨过程推断在持续增强
- C++ 对象模型恢复是“线索级”（object-like/vtable-like），非完整类层次恢复
- 异常恢复目前主要是 unwind/元数据摘要，不是完整 try/catch 结构化恢复

## 8. 常见问题

### Q1: 端口被占用导致启动失败怎么办？

优先使用 `scripts/run_dev_stack.sh`，会自动挑选空闲端口。

### Q2: 我想让前端连到指定后端端口？

可设置：

```bash
cd apps/web
VITE_PROXY_TARGET=http://127.0.0.1:8001 npm run dev
```

### Q3: 在 WSL 里运行，是否只能分析 WSL 里的 exe？

不是。只要后端进程能访问到路径就能分析：

- WSL 本地路径（例如 `/home/...`）
- Windows 挂载路径（例如 `/mnt/c/...`、`/mnt/d/...`）

工作区“自动扫描可反编译程序”会优先扫描这些可访问路径并按优先级排序。

### Q4: 为什么有些解释会标 low-confidence？

这是刻意设计：当证据不足时系统会显式降低置信度，避免“编造确定性结论”。
