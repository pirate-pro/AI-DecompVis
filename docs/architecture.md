# AI-DecompVis Architecture (P1/P2 merge stage)

## Core boundary (unchanged)

`core/aidecomp_core` remains the only analysis source of truth.

Owned by C++ core:
- PE/COFF load (headers/sections/RVA/VA/entry/import/export)
- byte decode backend (x86/x64)
- function discovery (entry + call targets)
- CFG/call graph/stack effect/stack balance
- stack slot + calling convention hint
- pseudo-code and evidence refs
- string extraction and path summaries

Not owned by C++ core:
- project/workspace/session APIs
- persistence
- UI rendering
- AI provider orchestration

## Bridge boundary

`core/aidecomp_py` (pybind11):
- exposes `analyze(...)` and `analyze_pe_file(...)`
- exports Program/Function/... DTOs
- no analysis duplication in Python

## Platform boundary

`services/aidecomp_api` owns:
- REST API
- runtime mode selection (embedded vs daemon)
- SQLite persistence
- task progress (SSE)
- explanation orchestration

## Runtime modes

- embedded: FastAPI -> pybind11 -> C++ core
- daemon: FastAPI -> gRPC -> aidecompd -> C++ core

Proto contract:
- `shared/proto/aidecomp_runtime.proto`
- includes AnalyzeBinary/GetProgramSummary/GetFunction/GetCFG/GetStackFrame/GetExplanation/Apply* methods

## Multi-entry

All entry points reuse same backend contract:
- Web app (`apps/web`)
- Desktop Electron (`apps/desktop-electron`)
- VS Code plugin (`plugins/vscode`)
- future IDA/Ghidra adapters

## Data model source and mirrors

Source of truth: C++ structs (`models.hpp`) and pybind DTOs.
Mirrors:
- Python pydantic models (`services/aidecomp_api/aidecomp_api/models.py`)
- TypeScript models (`apps/web/src/lib/types.ts`)

## Persistence

SQLite (`data/aidecompvis.db`):
- projects
- samples
- sessions
- annotations
- bookmarks
- renames
- ui_state
