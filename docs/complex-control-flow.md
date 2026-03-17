# Complex Control Flow (Current Scope)

## Covered

- indirect call / indirect branch 基础识别
- jump-table-like 分支候选信号（`has_switch_candidate`）
- import thunk 基础识别
- no-return hint（import 名称 + 用户约束）
- tailcall candidate hint

## Fallback policy

当目标无法可靠恢复时：
- 在 xref/evidence 中明确 `unsupported` 或低置信度
- 不编造 target
- 伪代码允许保守表达（helper/goto/unsupported 风格）

## Real sample status

- `real_pe_switch_x64` 提供 jump-table-like 真实 PE 样本
- 回归中验证 `has_switch_candidate` 与 `has_indirect_control`

## Limitations

- jump table 目标集恢复仍是启发式
- out-of-function jump 仅做保守处理
- unwind/exception metadata 暂未形成完整控制流恢复
