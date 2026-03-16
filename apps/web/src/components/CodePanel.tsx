import type { Func } from "../lib/types";

type Props = {
  func: Func;
  selectedBlockId: string;
  selectedInstructionAddress: number | null;
  onSelectInstruction: (address: number) => void;
};

function formatAddress(address: number): string {
  return `0x${address.toString(16)}`;
}

export function CodePanel({ func, selectedBlockId, selectedInstructionAddress, onSelectInstruction }: Props) {
  return (
    <div className="code-grid">
      <section className="panel">
        <h3>Assembly</h3>
        <div className="scroll-zone">
          {func.blocks.map((block) => (
            <div key={block.id} className={block.id === selectedBlockId ? "asm-block selected" : "asm-block"}>
              <div className="asm-block-title">{block.id}</div>
              {block.instructions.map((inst) => {
                const active = inst.address === selectedInstructionAddress;
                return (
                  <button
                    key={inst.address}
                    className={active ? "asm-line active" : "asm-line"}
                    onClick={() => onSelectInstruction(inst.address)}
                  >
                    <span>{formatAddress(inst.address)}</span>
                    <span>{inst.text}</span>
                  </button>
                );
              })}
            </div>
          ))}
        </div>
      </section>

      <section className="panel">
        <h3>Pseudo Code</h3>
        <div className="scroll-zone pseudo-zone">
          {func.pseudo_code.map((line, index) => {
            const isBlockLabel = line.trim().endsWith(":");
            const highlight = line.startsWith(selectedBlockId + ":") || (!isBlockLabel && line.includes(selectedBlockId));
            return (
              <div key={`${line}-${index}`} className={highlight ? "pseudo-line highlighted" : "pseudo-line"}>
                {line}
              </div>
            );
          })}
        </div>
      </section>
    </div>
  );
}
