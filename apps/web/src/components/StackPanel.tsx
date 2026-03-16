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
      <h3>Stack / Registers / Meta</h3>
      <div className="stack-section">
        <p>
          Frame Size: <strong>{func.stack_frame.frame_size}</strong> bytes
        </p>
        <p>
          Min Depth: <strong>{func.stack_frame.min_depth}</strong> | Max Depth: <strong>{func.stack_frame.max_depth}</strong>
        </p>
        <p>
          Stack Balanced: <strong>{func.stack_frame.balanced ? "yes" : "no"}</strong>
        </p>
        <p>
          Current Delta: <strong>{selectedInstruction ? signed(selectedInstruction.stack_delta) : "-"}</strong>
        </p>
        <p>
          Current Cumulative: <strong>{selectedInstruction ? selectedInstruction.cumulative_stack : "-"}</strong>
        </p>
        <p>Stack Note: {stackEvent?.note ?? "Select an instruction"}</p>
      </div>

      <div className="meta-grid">
        <div>
          <h4>Registers (teaching view)</h4>
          <ul>
            <li>RSP: tracked by stack model</li>
            <li>RBP: frame base candidate</li>
            <li>RAX: value unknown in static pass</li>
            <li>RDI: observed in compare/call path</li>
          </ul>
        </div>

        <div>
          <h4>Current Node Meta</h4>
          <p>Block: {selectedBlock?.id ?? "-"}</p>
          <p>Instructions: {selectedBlock?.instructions.length ?? 0}</p>
          <p>Calling Conv: {func.calling_convention_hint || "unknown"}</p>
          <p>
            Params/Locals: {func.params_hint}/{func.locals_hint}
          </p>
          <p>Callers/Callees: {func.callers.length}/{func.callees.length}</p>
          <p>
            Outgoing:
            {selectedBlock?.outgoing_edges.length
              ? selectedBlock.outgoing_edges.map((edge) => ` ${edge.condition}->${edge.to_block}`).join(" |")
              : " none"}
          </p>
        </div>
      </div>

      <div>
        <h4>Stack Slots</h4>
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
