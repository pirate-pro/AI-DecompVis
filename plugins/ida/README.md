# IDA Adapter (future)

## Host contract expectation

Input from IDA:
- current binary path
- current function VA
- selected basic block / instruction VA
- user action: annotate / rename / bookmark / explain

Backend expectation:
- `GetProgramSummary`
- `GetFunction`
- `GetCFG`
- `GetStackFrame`
- `GetExplanation`
- `ApplyAnnotation/Rename/Bookmark`

Output to IDA UI:
- function metadata and call graph hints
- block/instruction evidence-linked explanation
- stack slot and calling convention hints

## Adapter points

- `ida_loader.py`: collect host context and open project/session
- `ida_panel.py`: side panel rendering explanation and CFG summary
- `ida_sync.py`: optional sync host comments <-> AI-DecompVis annotations

## Note

This directory intentionally remains thin-client only; no core analysis logic should live here.
