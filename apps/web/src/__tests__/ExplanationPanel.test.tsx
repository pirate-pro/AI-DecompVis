import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";

import { ExplanationPanel } from "../components/ExplanationPanel";

test("evidence click triggers callback", async () => {
  const onSelectEvidence = vi.fn();

  render(
    <ExplanationPanel
      beginnerMode={false}
      onToggleBeginnerMode={() => {}}
      instructionExplanation={{
        id: "exp-inst",
        level: "instruction",
        confidence: 0.82,
        low_confidence: false,
        low_confidence_reason: "",
        text: "instruction explanation",
        evidence_refs: [
          {
            id: "ev-1",
            summary: "evidence summary",
            evidence_type: "instruction",
            confidence: 0.8,
            instruction_addresses: [4096],
            edge_ids: [],
            block_ids: ["B0"],
            related_imports: [],
            related_strings: [],
            related_path_summary: "",
            stack_event_addresses: [],
            unsupported_reason: ""
          }
        ]
      }}
      blockExplanation={null}
      pathExplanation={null}
      functionExplanation={null}
      projectState={{ project_id: "p1", annotations: [], renames: [], bookmarks: [] }}
      onSelectEvidence={onSelectEvidence}
      onCreateAnnotation={async () => {}}
      onCreateBookmark={async () => {}}
      onCreateRename={async () => {}}
    />
  );

  expect(screen.getByText(/置信度: 82%/i)).toBeInTheDocument();
  await userEvent.click(screen.getByRole("button", { name: /ev-1/i }));
  expect(onSelectEvidence).toHaveBeenCalledTimes(1);
});
