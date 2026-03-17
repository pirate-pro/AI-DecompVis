# User-Guided Reanalysis

## Objective

让用户约束能够进入核心分析链路，而不是停留在 UI 注释层。

## Current supported constraints

- `no_return`
- `indirect_target`
- `type_override`（当前用于摘要/解释语义增强）
- `value_range` / `this_pointer`（字段已保留，后续 pass 将使用）

## Data flow

1. 用户在 Web/插件提交约束
2. 约束持久化到 SQLite (`analysis_constraints`)
3. 再次分析时，FastAPI 将约束注入 AnalyzeRequest
4. C++ core 在构建函数与摘要时应用约束
5. 新 program/function/evidence 返回 UI/插件

## Current closed loop

- Web: 标记 no-return / 添加 indirect target -> 触发重分析 -> 结果刷新
- VS Code: `Apply No-Return Constraint` -> 触发重分析 -> 刷新当前 session

## Limitations

- 目前约束驱动范围仍有限（主要影响 target 解析与 no-return）
- 复杂值域约束尚未深入进入 IR simplification/type propagation
