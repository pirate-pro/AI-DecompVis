# Plugin Strategy (P4/P5)

## Goal

Keep plugins as thin host adapters over shared backend contracts.

## Shared contract surface

Plugins consume:
- workspace/project/session discovery
- program/function/IR-summary/xref/explanation DTOs
- mutation APIs (`annotation` / `bookmark` / `rename`)
- user-guided constraints + reanalysis trigger

Transports:
- REST (current primary path)
- gRPC contract reserved for future direct-host adapters

## Why thin

- C++ core remains the only analysis source of truth
- avoids duplicated decoder/IR/SSA logic in host plugins
- keeps confidence/evidence semantics consistent across Web/Desktop/Plugin

## VS Code status

Current VS Code plugin supports:
- select `project -> session`
- function tree + search
- function summary and explanation webviews
- annotation/bookmark write-back
- apply `no_return` constraint and trigger reanalysis refresh

## IDA / Ghidra status

- current stage keeps README + contract expectations only
- planned adapters should call backend contracts, not embed analysis logic
