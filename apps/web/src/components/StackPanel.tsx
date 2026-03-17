import type { BasicBlock, Func, Instruction } from "../lib/types";

type Props = {
  func: Func;
  selectedBlock: BasicBlock | undefined;
  selectedInstruction: Instruction | undefined;
};

function signed(value: number): string {
  return value > 0 ? `+${value}` : `${value}`;
}

export function StackPanel({ func, selectedBlock, selectedInstruction }: Props) {
  const stackEvent = selectedInstruction
    ? func.stack_frame.events.find((event) => event.instruction_address === selectedInstruction.address)
    : undefined;

  return (
    <div className="panel stack-panel">
      <h3>栈 / 寄存器 / 节点元信息</h3>
      <div className="stack-section">
        <p>
          栈帧大小: <strong>{func.stack_frame.frame_size}</strong> 字节
        </p>
        <p>
          最小深度: <strong>{func.stack_frame.min_depth}</strong> | 最大深度: <strong>{func.stack_frame.max_depth}</strong>
        </p>
        <p>
          栈是否平衡: <strong>{func.stack_frame.balanced ? "是" : "否"}</strong>
        </p>
        <p>
          当前指令栈增量: <strong>{selectedInstruction ? signed(selectedInstruction.stack_delta) : "-"}</strong>
        </p>
        <p>
          当前累计栈深: <strong>{selectedInstruction ? selectedInstruction.cumulative_stack : "-"}</strong>
        </p>
        <p>栈说明: {stackEvent?.note ?? "请先选择一条指令"}</p>
      </div>

      <div className="meta-grid">
        <div>
          <h4>寄存器（教学视图）</h4>
          <ul>
            <li>RSP: 由栈模型跟踪</li>
            <li>RBP: 可能的栈帧基址</li>
            <li>RAX: 静态分析下值可能未知</li>
            <li>RDI: 在比较/调用路径中被观测</li>
          </ul>
        </div>

        <div>
          <h4>当前节点信息</h4>
          <p>基本块: {selectedBlock?.id ?? "-"}</p>
          <p>指令数: {selectedBlock?.instructions.length ?? 0}</p>
          <p>调用约定: {func.calling_convention_hint || "unknown"}</p>
          <p>函数置信度: {(func.confidence * 100).toFixed(0)}%</p>
          <p>
            参数/局部变量: {func.params_hint}/{func.locals_hint}
          </p>
          <p>调用者/被调者: {func.callers.length}/{func.callees.length}</p>
          <p>Xref 入/出: {func.xref_in_count}/{func.xref_out_count}</p>
          <p>导入/字符串 Xref: {func.import_xref_count}/{func.string_xref_count}</p>
          <p>
            出边:
            {selectedBlock?.outgoing_edges.length
              ? selectedBlock.outgoing_edges.map((edge) => ` ${edge.condition}->${edge.to_block}`).join(" |")
              : " 无"}
          </p>
        </div>
      </div>

      <div>
        <h4>栈槽</h4>
        <ul>
          {func.stack_slots.slice(0, 8).map((slot) => (
            <li key={`${slot.role}-${slot.offset}`}>
              {slot.name} ({slot.role}) @ {slot.offset}
            </li>
          ))}
        </ul>
      </div>
    </div>
  );
}
