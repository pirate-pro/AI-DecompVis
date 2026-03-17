# AI-DecompVis Architecture (P4/P5)

## 1. Core boundary

`core/aidecomp_core` is still the single analysis source of truth.

C++ core owns:
- PE/COFF loading and image model
- decoder abstraction and backend integration
- function discovery / xref / call graph
- CFG / stack effect / stack frame / stack balance
- architecture-independent IR lifting
- SSA + MemorySSA-like model (intraprocedural)
- pseudo-code and path summary generation
- evidence/confidence raw facts
- user-guided constraints applied during analysis

C++ core does **not** own:
- REST API
- project/workspace persistence
- UI state
- AI provider orchestration

## 2. Core pipeline

Current pipeline:
1. PE load (`headers/sections/imports/exports/strings`)
2. decode (primary: `objdump-intel`, fallback: `x86-rule`)
3. function discovery (recursive descent + safe fallback)
4. per-function analysis:
   - block split + CFG
   - stack/frame facts
   - instruction -> IR lifting
   - SSA + MemorySSA-like
   - function summary + evidence refs
   - pseudo-code / path summaries
5. program-level xrefs and explanation facts

## 3. Bridge boundary

`core/aidecomp_py` is a thin pybind11 bridge:
- exposes core entrypoints
- mirrors Program/Function/IR/SSA/Evidence/Constraint DTOs
- no duplicated decompiler passes

## 4. Platform boundary

`services/aidecomp_api` owns:
- workspace/project/session lifecycle
- SQLite persistence (including constraints)
- runtime provider switch (embedded/daemon)
- task orchestration + SSE progress + cancellation endpoint
- explanation provider orchestration

FastAPI does **not** implement decode/IR/SSA/type recovery passes.

## 5. Runtime boundary

Embedded:
- `client -> FastAPI -> pybind11 -> C++ core`

Daemon:
- `client -> FastAPI -> gRPC -> aidecompd -> pybind11 -> C++ core`
- proto: `shared/proto/aidecomp_runtime.proto`
- has `api_version` contract and cancel RPC

## 6. Thin clients

- Web (`apps/web`)
- Desktop (`apps/desktop-electron`)
- VS Code (`plugins/vscode`)

All clients remain thin:
- consume backend DTO/contracts
- render evidence/IR/SSA metadata
- submit user constraints and trigger reanalysis
- never duplicate core analysis logic
