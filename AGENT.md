# AI-DecompVis Agent Rules

## Core rule

C++ core is the only analysis source of truth.

Never move real analysis logic into Python or frontend code.
Python/FastAPI is only for:
- platform services
- AI orchestration
- storage/session APIs
- presentation-friendly adaptation

## Product goal

AI-DecompVis is for beginner-friendly reverse-engineering education and program understanding.

Optimize for:
1. control-flow clarity
2. stack visualization
3. explainable guidance
4. reusable architecture for web, desktop, and plugins

Do not optimize first for perfect source reconstruction.

## Layer boundaries

### C++ core
Owns:
- decoding
- CFG
- call relations
- stack effect
- pseudo-code structuring
- evidence generation

### Python/FastAPI
Owns:
- REST API
- sessions
- projects
- annotations / rename / bookmarks
- AI explanation orchestration

### Frontend
Owns:
- visualization
- interaction
- beginner-mode UX
- cross-highlighting

### Plugins / desktop adapters
Own only host integration and UI entrypoints.
They must not duplicate core analysis logic.

## Runtime strategy

Short term:
- FastAPI + pybind11

Long term:
- local daemon + gRPC
- thin clients for IDE / RE plugins

Design the repo so this migration is easy.

## UX priorities

The default UI should make these four panes obvious:
- CFG / navigation
- assembly / pseudo-code
- stack / registers
- explanations / hints

Beginner mode should prefer plain language.

## Safety

This project is for authorized analysis, education, debugging, and research.
Do not add offensive workflows or evasion-oriented features.

## Next-stage repository rules

- Preserve the current P0 user flows while extending toward real binary analysis.
- Treat C++ core as the single source of truth for analysis.
- Do not move analysis logic into Python or frontend code.
- Prefer real PE analysis over UI polish when tradeoffs appear.
- Keep FastAPI as platform/orchestration only.
- Keep desktop and plugin implementations thin; reuse shared contracts.
- Update docs whenever runtime modes or plugin contracts change.
- Add tests for any new analysis feature before considering the task complete.