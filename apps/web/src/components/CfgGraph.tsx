import type { Func } from "../lib/types";

type Props = {
  func: Func;
  selectedBlockId: string;
  onSelectBlock: (blockId: string) => void;
};

const NODE_W = 120;
const NODE_H = 52;

export function CfgGraph({ func, selectedBlockId, onSelectBlock }: Props) {
  const positions = new Map<string, { x: number; y: number }>();
  func.blocks.forEach((block, index) => {
    const row = Math.floor(index / 2);
    const col = index % 2;
    positions.set(block.id, { x: 30 + col * 170, y: 30 + row * 120 });
  });

  const height = Math.max(220, 60 + Math.ceil(func.blocks.length / 2) * 120);

  return (
    <div className="cfg-shell">
      <svg viewBox={`0 0 360 ${height}`} className="cfg-canvas" role="img" aria-label="cfg graph">
        <defs>
          <marker id="arrow" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">
            <path d="M 0 0 L 10 5 L 0 10 z" fill="#f95d2a" />
          </marker>
        </defs>
        {func.edges.map((edge) => {
          const from = positions.get(edge.from_block);
          const to = positions.get(edge.to_block);
          if (!from || !to) return null;
          return (
            <g key={edge.id}>
              <line
                x1={from.x + NODE_W / 2}
                y1={from.y + NODE_H}
                x2={to.x + NODE_W / 2}
                y2={to.y}
                stroke="#f95d2a"
                strokeWidth="2"
                markerEnd="url(#arrow)"
              />
              <text x={(from.x + to.x) / 2 + NODE_W / 2 - 20} y={(from.y + to.y) / 2 + 10} className="edge-label">
                {edge.condition}
              </text>
            </g>
          );
        })}

        {func.blocks.map((block) => {
          const p = positions.get(block.id)!;
          const selected = block.id === selectedBlockId;
          return (
            <g key={block.id} onClick={() => onSelectBlock(block.id)} className="cfg-node-group">
              <rect x={p.x} y={p.y} width={NODE_W} height={NODE_H} rx={12} className={selected ? "cfg-node selected" : "cfg-node"} />
              <text x={p.x + 12} y={p.y + 22} className="node-title">
                {block.id}
              </text>
              <text x={p.x + 12} y={p.y + 40} className="node-subtitle">
                {block.instructions.length} instr
              </text>
            </g>
          );
        })}
      </svg>
    </div>
  );
}
