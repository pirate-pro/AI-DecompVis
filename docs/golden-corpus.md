# Golden Corpus

## Purpose

用稳定断言衡量“核心是否退化”，而不只看能否运行。

## Location

- assertions: `tests/golden/*.assertions.json`
- tests: `tests/python/test_golden_corpus.py`
- samples: `samples/real_pe/*.exe`

## Current corpus

- `real_pe_minimal_x64`
  - 基础函数发现、sections、strings、xref、entry calling convention
- `real_pe_switch_x64`
  - jump-table-like 样本，验证间接控制流候选信号

## Assertion style

当前断言偏结构与语义信号：
- min function count
- required sections
- xref/string counts
- key metadata hints（calling convention / switch candidate）

## Next

- 增加 O0/O2/O3 编译样本
- 增加 import-heavy 与 C++ 样本
- 增加 pseudo-code snapshot 与 unsupported 行为断言
