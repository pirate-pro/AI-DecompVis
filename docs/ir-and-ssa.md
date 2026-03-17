# IR and SSA

## Goal

在 machine instruction 与伪代码之间提供稳定的、架构无关的中间层，支撑可追溯解释与后续优化 pass。

## Current IR coverage

当前 IR 节点支持：
- register/stack/memory 读写
- const / unary-binary style ops
- cast (`zext` / `sext`)
- compare + flag write
- direct call / indirect call
- branch / conditional branch / return
- phi

每条 IR 指令保留：
- `source_address`（原始 machine instruction 地址）
- `source_block_id`
- `evidence_id`

## SSA

当前 SSA 为函数内（intraprocedural）版本：
- trackable 值（reg/stack/mem-like）版本化
- merge 节点插入 phi
- 暴露 def-use/use-def 映射（`SSADefUse`）

## MemorySSA-like

当前内存版本模型包含：
- `MemoryDef`
- `MemoryUse`
- `MemoryPhi`

可用于：
- 解释增强（内存副作用可追溯）
- 后续类型传播与结构化 pass 的事实输入

## Limitations

- 跨过程 SSA/MemorySSA 尚未实现
- alias analysis 仍是启发式
- 部分复杂寄存器别名尚未精细建模
