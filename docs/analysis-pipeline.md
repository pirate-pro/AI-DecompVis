# Analysis Pipeline (current)

1. PE load:
   - parse DOS/NT headers, sections, image base, entry
   - parse imports/exports
   - extract ASCII/UTF16LE strings

2. Decode:
   - image decode via decoder abstraction
   - primary backend: `objdump-intel`
   - fallback backend: in-core `x86-rule`

3. Function discovery:
   - recursive descent from entry + call targets
   - fallback prologue scan

4. Per-function base analysis:
   - block split / CFG / edges
   - stack effect / frame / balance
   - calling convention + params/locals/stack-slot hints

5. IR/SSA stage:
   - instruction lifting to architecture-neutral IR
   - SSA versioning + phi insertion on merges
   - MemorySSA-like model (`MemoryDef/MemoryUse/MemoryPhi`)
   - def-use / use-def facts for explanation and summaries

6. Program-level relations:
   - code/import/string xrefs
   - import thunk mapping
   - callers/callees and summary aggregation

7. Output facts:
   - pseudo-code + path summaries
   - evidence refs with confidence/unsupported hints
   - function summary + applied constraint traces
