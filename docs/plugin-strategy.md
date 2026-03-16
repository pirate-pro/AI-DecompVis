# Plugin Strategy

## Goal

All plugins are thin adapters over a shared local backend contract.

## Shared backend contract

- Analyze and load sessions
- Retrieve program/function/CFG/stack/explanation DTO
- Apply annotation/rename/bookmark mutations

Contract surfaces:
- REST (current)
- gRPC (`shared/proto/aidecomp_runtime.proto`) for future stable adapter line

## Why thin clients

- Prevent analysis logic fragmentation across hosts
- Keep C++ core as single source of truth
- Simplify consistency of explanations and evidence refs

## Current status

- VS Code: MVP implemented (`plugins/vscode`)
- IDA/Ghidra: architecture and expected host contract documented

## Next for plugins

1. Add auth-free local session discovery command.
2. Add jump-to-basic-block interaction from host selection.
3. Add lightweight caching and reconnection handling for daemon mode.
