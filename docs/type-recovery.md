# Type Recovery (Current Scope)

## Current signals

当前类型与 ABI 恢复主要基于以下事实：
- calling convention hints（x64/cdecl/stdcall/fastcall）
- stack frame + stack slot 角色（param/local/saved）
- import 语义（例如 no-return-like API）
- string xref 与 pointer-like usage
- IR/SSA def-use 关系中的读写模式

## Output surface

当前会反映到：
- `Function.calling_convention_hint`
- `params_hint` / `locals_hint`
- `stack_slots`
- `variables`（最小类型标签）
- `FunctionSummary`（return/no_return/side_effect/imported_semantics）

## User override hooks

已预留并部分生效：
- `no_return`
- `type_override`（当前作为语义标签参与说明）
- `value_range`（保留字段，后续用于传播）

## Limitations

- 类型系统仍以 hint 为主，未形成完整 lattice + fixpoint
- struct-field 精细恢复尚未完成
- 跨函数类型传播仍有限
