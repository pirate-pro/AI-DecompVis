# Ghidra Adapter (future)

## Host contract expectation

Input from Ghidra:
- program file path
- function symbol/address
- selected instruction or block

Backend expectation:
- project/session open
- function summary and CFG retrieval
- stack frame + path explanation retrieval
- annotation/rename/bookmark mutation APIs

Output in Ghidra:
- docked panel with function list
- explanation panel with evidence refs
- navigation from path summary to basic block

## Adapter points

- `ghidra_bridge.java`: host integration and API client
- `ghidra_panel.java`: UI entry
- `ghidra_mapping.md`: VA/RVA mapping rules for UI links

## Note

Keep adapter thin; all disassembly/decompilation reasoning remains in C++ core.
