import { FormEvent, useState } from "react";

import type { EvidenceRef, Explanation, ProjectState } from "../lib/types";

type Props = {
  beginnerMode: boolean;
  onToggleBeginnerMode: () => void;
  instructionExplanation: Explanation | null;
  blockExplanation: Explanation | null;
  pathExplanation: Explanation | null;
  functionExplanation: Explanation | null;
  projectState: ProjectState | null;
  onSelectEvidence: (evidence: EvidenceRef) => void;
  onCreateAnnotation: (text: string) => Promise<void>;
  onCreateBookmark: (note: string) => Promise<void>;
  onCreateRename: (newName: string) => Promise<void>;
};

export function ExplanationPanel({
  beginnerMode,
  onToggleBeginnerMode,
  instructionExplanation,
  blockExplanation,
  pathExplanation,
  functionExplanation,
  projectState,
  onSelectEvidence,
  onCreateAnnotation,
  onCreateBookmark,
  onCreateRename
}: Props) {
  const [annotationText, setAnnotationText] = useState("");
  const [bookmarkNote, setBookmarkNote] = useState("");
  const [renameText, setRenameText] = useState("");

  const submit = async (event: FormEvent, type: "annotation" | "bookmark" | "rename") => {
    event.preventDefault();
    if (type === "annotation" && annotationText.trim()) {
      await onCreateAnnotation(annotationText.trim());
      setAnnotationText("");
    }
    if (type === "bookmark" && bookmarkNote.trim()) {
      await onCreateBookmark(bookmarkNote.trim());
      setBookmarkNote("");
    }
    if (type === "rename" && renameText.trim()) {
      await onCreateRename(renameText.trim());
      setRenameText("");
    }
  };

  const evidence = [...(instructionExplanation?.evidence_refs ?? []), ...(blockExplanation?.evidence_refs ?? []), ...(pathExplanation?.evidence_refs ?? [])]
    .filter((item, index, arr) => arr.findIndex((candidate) => candidate.id === item.id) === index)
    .slice(0, 8);

  const renderExplanation = (title: string, explanation: Explanation | null, fallback: string) => (
    <div>
      <h4>{title}</h4>
      <p>{explanation?.text ?? fallback}</p>
      {explanation ? (
        <p className="confidence-line">
          置信度: {(explanation.confidence * 100).toFixed(0)}%
          {explanation.low_confidence ? ` | 低置信度: ${explanation.low_confidence_reason || "证据不足"}` : ""}
        </p>
      ) : null}
    </div>
  );

  return (
    <div className="panel explanation-panel">
      <div className="explain-header">
        <h3>AI 解释 / 新手提示</h3>
        <button className={beginnerMode ? "toggle active" : "toggle"} onClick={onToggleBeginnerMode}>
          新手模式: {beginnerMode ? "开" : "关"}
        </button>
      </div>

      <div className="explain-grid">
        {renderExplanation("指令级", instructionExplanation, "选择一条指令后显示解释。")}
        {renderExplanation("基本块级", blockExplanation, "选择一个基本块后显示解释。")}
        {renderExplanation("路径级", pathExplanation, "选择基本块后显示入口到当前块的路径摘要。")}
        {renderExplanation("函数级", functionExplanation, "选择函数后显示整体解释。")}
      </div>

      <div className="evidence-zone">
        <h4>证据</h4>
        <ul>
          {evidence.map((ev) => (
            <li key={ev.id}>
              <button type="button" className="evidence-link" onClick={() => onSelectEvidence(ev)}>
                {ev.id} [{ev.evidence_type || "fact"} / {(ev.confidence * 100).toFixed(0)}%]
              </button>
              <div>{ev.summary}</div>
              {ev.unsupported_reason ? <small>不支持/不确定: {ev.unsupported_reason}</small> : null}
            </li>
          ))}
        </ul>
      </div>

      <div className="ops-row">
        <form onSubmit={(e) => submit(e, "annotation")}>
          <input value={annotationText} onChange={(e) => setAnnotationText(e.target.value)} placeholder="添加注释" />
          <button type="submit">保存注释</button>
        </form>

        <form onSubmit={(e) => submit(e, "rename")}>
          <input value={renameText} onChange={(e) => setRenameText(e.target.value)} placeholder="重命名当前目标" />
          <button type="submit">保存重命名</button>
        </form>

        <form onSubmit={(e) => submit(e, "bookmark")}>
          <input value={bookmarkNote} onChange={(e) => setBookmarkNote(e.target.value)} placeholder="书签备注" />
          <button type="submit">保存书签</button>
        </form>
      </div>

      <div className="ops-state">
        <span>注释: {projectState?.annotations.length ?? 0}</span>
        <span>重命名: {projectState?.renames.length ?? 0}</span>
        <span>书签: {projectState?.bookmarks.length ?? 0}</span>
      </div>
    </div>
  );
}
