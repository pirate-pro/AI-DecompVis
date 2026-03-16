import { FormEvent, useState } from "react";

import type { Explanation, ProjectState } from "../lib/types";

type Props = {
  beginnerMode: boolean;
  onToggleBeginnerMode: () => void;
  instructionExplanation: Explanation | null;
  blockExplanation: Explanation | null;
  pathExplanation: Explanation | null;
  functionExplanation: Explanation | null;
  projectState: ProjectState | null;
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

  return (
    <div className="panel explanation-panel">
      <div className="explain-header">
        <h3>AI Explanation / Beginner Hints</h3>
        <button className={beginnerMode ? "toggle active" : "toggle"} onClick={onToggleBeginnerMode}>
          Beginner Mode: {beginnerMode ? "ON" : "OFF"}
        </button>
      </div>

      <div className="explain-grid">
        <div>
          <h4>Instruction</h4>
          <p>{instructionExplanation?.text ?? "Select instruction to load explanation."}</p>
        </div>
        <div>
          <h4>Block</h4>
          <p>{blockExplanation?.text ?? "Select block to load explanation."}</p>
        </div>
        <div>
          <h4>Path</h4>
          <p>{pathExplanation?.text ?? "Select block to load path summary."}</p>
        </div>
        <div>
          <h4>Function</h4>
          <p>{functionExplanation?.text ?? "Select function to load explanation."}</p>
        </div>
      </div>

      <div className="evidence-zone">
        <h4>Evidence</h4>
        <ul>
          {(instructionExplanation?.evidence_refs ?? []).slice(0, 3).map((ev) => (
            <li key={ev.id}>
              {ev.id}: {ev.summary}
            </li>
          ))}
        </ul>
      </div>

      <div className="ops-row">
        <form onSubmit={(e) => submit(e, "annotation")}> 
          <input value={annotationText} onChange={(e) => setAnnotationText(e.target.value)} placeholder="Add annotation" />
          <button type="submit">Save Annotation</button>
        </form>

        <form onSubmit={(e) => submit(e, "rename")}> 
          <input value={renameText} onChange={(e) => setRenameText(e.target.value)} placeholder="Rename current target" />
          <button type="submit">Save Rename</button>
        </form>

        <form onSubmit={(e) => submit(e, "bookmark")}> 
          <input value={bookmarkNote} onChange={(e) => setBookmarkNote(e.target.value)} placeholder="Bookmark note" />
          <button type="submit">Save Bookmark</button>
        </form>
      </div>

      <div className="ops-state">
        <span>Annotations: {projectState?.annotations.length ?? 0}</span>
        <span>Renames: {projectState?.renames.length ?? 0}</span>
        <span>Bookmarks: {projectState?.bookmarks.length ?? 0}</span>
      </div>
    </div>
  );
}
