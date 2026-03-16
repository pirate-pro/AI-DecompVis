import { useEffect, useMemo, useState } from "react";

import { CfgGraph } from "./components/CfgGraph";
import { CodePanel } from "./components/CodePanel";
import { ExplanationPanel } from "./components/ExplanationPanel";
import { StackPanel } from "./components/StackPanel";
import {
  createAnalysisTask,
  createAnnotation,
  createBookmark,
  createProject,
  createRename,
  createTaskEventSource,
  fetchAnalysis,
  fetchExplanation,
  fetchProjectSamples,
  fetchProjectState,
  fetchProjects,
  fetchRuntime,
  fetchSamples,
  fetchUIState,
  getTaskStatus,
  saveUIState
} from "./lib/api";
import type { Explanation, Func, Program, ProjectInfo, ProjectState, RuntimeInfo, SampleInfo, SampleRecord, TaskStatus } from "./lib/types";
import "./styles/app.css";

function newSessionId() {
  return `session-${Date.now()}`;
}

export default function App() {
  const [runtime, setRuntime] = useState<RuntimeInfo | null>(null);
  const [samples, setSamples] = useState<SampleInfo[]>([]);
  const [projects, setProjects] = useState<ProjectInfo[]>([]);
  const [selectedProjectId, setSelectedProjectId] = useState<string>("default");
  const [projectNameInput, setProjectNameInput] = useState<string>("My Project");
  const [projectSamples, setProjectSamples] = useState<SampleRecord[]>([]);

  const [selectedSampleId, setSelectedSampleId] = useState<string>("demo_stack_branch");
  const [customBinaryPath, setCustomBinaryPath] = useState<string>("");

  const [sessionId, setSessionId] = useState<string>(newSessionId());
  const [taskStatus, setTaskStatus] = useState<TaskStatus | null>(null);

  const [program, setProgram] = useState<Program | null>(null);
  const [selectedFunctionName, setSelectedFunctionName] = useState<string>("");
  const [selectedBlockId, setSelectedBlockId] = useState<string>("");
  const [selectedInstructionAddress, setSelectedInstructionAddress] = useState<number | null>(null);

  const [instructionExplanation, setInstructionExplanation] = useState<Explanation | null>(null);
  const [blockExplanation, setBlockExplanation] = useState<Explanation | null>(null);
  const [pathExplanation, setPathExplanation] = useState<Explanation | null>(null);
  const [functionExplanation, setFunctionExplanation] = useState<Explanation | null>(null);
  const [projectState, setProjectState] = useState<ProjectState | null>(null);
  const [beginnerMode, setBeginnerMode] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    void (async () => {
      try {
        const [runtimeInfo, sampleList, projectList] = await Promise.all([fetchRuntime(), fetchSamples(), fetchProjects()]);
        setRuntime(runtimeInfo);
        setSamples(sampleList);
        setProjects(projectList);

        if (sampleList.length > 0) {
          const real = sampleList.find((s) => s.source_type === "real_pe");
          setSelectedSampleId(real?.sample_id ?? sampleList[0].sample_id);
        }

        if (projectList.length > 0) {
          setSelectedProjectId(projectList[0].project_id);
        }
      } catch (e) {
        setError(`bootstrap failed: ${(e as Error).message}`);
      }
    })();
  }, []);

  useEffect(() => {
    void (async () => {
      try {
        const [state, ui, sampleRecords] = await Promise.all([
          fetchProjectState(selectedProjectId),
          fetchUIState(selectedProjectId),
          fetchProjectSamples(selectedProjectId)
        ]);
        setProjectState(state);
        setBeginnerMode(ui.beginner_mode);
        setProjectSamples(sampleRecords);
      } catch {
        // keep default for new project
      }
    })();
  }, [selectedProjectId]);

  const selectedFunction: Func | undefined = useMemo(
    () => program?.functions.find((item) => item.name === selectedFunctionName),
    [program, selectedFunctionName]
  );

  const selectedBlock = selectedFunction?.blocks.find((block) => block.id === selectedBlockId);
  const selectedInstruction = selectedBlock?.instructions.find((inst) => inst.address === selectedInstructionAddress);

  const persistUIState = async (functionName: string, blockId: string, beginner: boolean) => {
    try {
      await saveUIState(selectedProjectId, {
        project_id: selectedProjectId,
        current_function: functionName,
        current_block: blockId,
        beginner_mode: beginner
      });
    } catch {
      // non-blocking
    }
  };

  const fetchAndApplyAnalysis = async (sid: string) => {
    const payload = await fetchAnalysis(sid);
    setProgram(payload.program);
    const firstFunction = payload.program.functions[0];
    const firstBlock = firstFunction?.entry_block_id || firstFunction?.blocks[0]?.id || "";
    const firstInstr = firstFunction?.blocks[0]?.instructions[0]?.address ?? null;

    setSelectedFunctionName(firstFunction?.name || "");
    setSelectedBlockId(firstBlock);
    setSelectedInstructionAddress(firstInstr);

    await persistUIState(firstFunction?.name || "", firstBlock, beginnerMode);
    setProjectState(await fetchProjectState(selectedProjectId));
    setProjectSamples(await fetchProjectSamples(selectedProjectId));
  };

  const runSelectedSample = async () => {
    setError(null);
    const sid = newSessionId();
    setSessionId(sid);
    setTaskStatus(null);

    const analyzePayload: { project_id: string; session_id: string; sample_id?: string; binary_path?: string } = {
      project_id: selectedProjectId,
      session_id: sid
    };

    if (customBinaryPath.trim()) {
      analyzePayload.binary_path = customBinaryPath.trim();
    } else {
      analyzePayload.sample_id = selectedSampleId;
    }

    try {
      const { task_id } = await createAnalysisTask({ analyze: analyzePayload });
      const source = createTaskEventSource(task_id);

      source.addEventListener("progress", (event) => {
        const update = JSON.parse((event as MessageEvent<string>).data) as TaskStatus;
        setTaskStatus(update);

        if (update.status === "done") {
          source.close();
          void fetchAndApplyAnalysis(sid);
        }
        if (update.status === "failed") {
          source.close();
          setError(update.detail || "analysis task failed");
        }
      });

      source.onerror = () => {
        source.close();
        void (async () => {
          const current = await getTaskStatus(task_id);
          setTaskStatus(current);
          if (current.status === "done") {
            await fetchAndApplyAnalysis(sid);
          }
          if (current.status === "failed") {
            setError(current.detail || "analysis task failed");
          }
        })();
      };
    } catch (e) {
      setError(`analysis failed: ${(e as Error).message}`);
    }
  };

  useEffect(() => {
    if (!selectedFunction) return;

    void (async () => {
      try {
        const functionExp = await fetchExplanation({
          session_id: sessionId,
          function_name: selectedFunction.name,
          level: "function",
          target_id: selectedFunction.name,
          beginner_mode: beginnerMode
        });
        setFunctionExplanation(functionExp);
      } catch {
        setFunctionExplanation(null);
      }
    })();
  }, [selectedFunction, beginnerMode, sessionId]);

  useEffect(() => {
    if (!selectedFunction || !selectedBlockId) return;

    void (async () => {
      try {
        const [blockExp, pathExp] = await Promise.all([
          fetchExplanation({
            session_id: sessionId,
            function_name: selectedFunction.name,
            level: "block",
            target_id: selectedBlockId,
            beginner_mode: beginnerMode
          }),
          fetchExplanation({
            session_id: sessionId,
            function_name: selectedFunction.name,
            level: "path",
            target_id: selectedBlockId,
            beginner_mode: beginnerMode
          })
        ]);
        setBlockExplanation(blockExp);
        setPathExplanation(pathExp);
      } catch {
        setBlockExplanation(null);
        setPathExplanation(null);
      }
      await persistUIState(selectedFunction.name, selectedBlockId, beginnerMode);
    })();
  }, [selectedFunction, selectedBlockId, beginnerMode, sessionId]);

  useEffect(() => {
    if (!selectedFunction || selectedInstructionAddress === null) return;

    void (async () => {
      try {
        const instExp = await fetchExplanation({
          session_id: sessionId,
          function_name: selectedFunction.name,
          level: "instruction",
          target_id: `0x${selectedInstructionAddress.toString(16)}`,
          beginner_mode: beginnerMode
        });
        setInstructionExplanation(instExp);
      } catch {
        setInstructionExplanation(null);
      }
    })();
  }, [selectedFunction, selectedInstructionAddress, beginnerMode, sessionId]);

  const activeTarget = (() => {
    if (selectedInstructionAddress !== null) {
      return { type: "instruction" as const, id: `0x${selectedInstructionAddress.toString(16)}` };
    }
    if (selectedBlockId) {
      return { type: "block" as const, id: selectedBlockId };
    }
    return { type: "function" as const, id: selectedFunctionName };
  })();

  return (
    <main className="app-root">
      <header className="top-bar">
        <div>
          <h1>AI-DecompVis</h1>
          <p>
            Runtime: {runtime?.mode ?? "..."}
            {runtime?.daemon_target ? ` @ ${runtime.daemon_target}` : ""}
          </p>
        </div>

        <div className="top-controls">
          <select value={selectedProjectId} onChange={(e) => setSelectedProjectId(e.target.value)}>
            <option value="default">default</option>
            {projects.map((project) => (
              <option key={project.project_id} value={project.project_id}>
                {project.project_id}
              </option>
            ))}
          </select>
          <input value={projectNameInput} onChange={(e) => setProjectNameInput(e.target.value)} placeholder="new project name" />
          <button
            onClick={async () => {
              const pid = `project-${Date.now()}`;
              const created = await createProject({ project_id: pid, name: projectNameInput || pid });
              const items = await fetchProjects();
              setProjects(items);
              setSelectedProjectId(created.project_id);
            }}
          >
            New Project
          </button>
        </div>
      </header>

      {taskStatus ? (
        <div className="task-progress panel">
          <strong>
            Task: {taskStatus.status} ({taskStatus.percent}%)
          </strong>
          <span>
            {taskStatus.stage} - {taskStatus.detail}
          </span>
          <div className="progress-bar">
            <div className="progress-fill" style={{ width: `${Math.max(0, Math.min(100, taskStatus.percent))}%` }} />
          </div>
        </div>
      ) : null}

      {error ? <div className="error-banner">{error}</div> : null}

      <section className="layout-grid">
        <aside className="panel left-pane">
          <h3>Workspace + Program Summary</h3>

          <div className="function-list">
            <select value={selectedSampleId} onChange={(e) => setSelectedSampleId(e.target.value)}>
              {samples.map((sample) => (
                <option key={sample.sample_id} value={sample.sample_id}>
                  {sample.sample_id} ({sample.source_type})
                </option>
              ))}
            </select>
            <button onClick={runSelectedSample}>Analyze</button>
          </div>

          <input value={customBinaryPath} onChange={(e) => setCustomBinaryPath(e.target.value)} placeholder="or local binary path" />

          <div className="summary-list">
            <p>Entry: {program ? `0x${program.entry_point.toString(16)}` : "-"}</p>
            <p>Functions: {program?.functions.length ?? 0}</p>
            <p>Sections: {program?.sections.length ?? 0}</p>
            <p>Imports: {program?.imports.length ?? 0}</p>
            <p>Strings: {program?.strings.length ?? 0}</p>
          </div>

          <div className="summary-list">
            <h4>Sections</h4>
            <ul>
              {(program?.sections ?? []).map((section) => (
                <li key={section.name}>
                  {section.name} ({section.kind})
                </li>
              ))}
            </ul>
          </div>

          <div className="summary-list">
            <h4>Recent Samples</h4>
            <ul>
              {projectSamples.slice(0, 5).map((sample) => (
                <li key={`${sample.sample_id}-${sample.created_at}`}>{sample.sample_id}</li>
              ))}
            </ul>
          </div>

          <div className="function-list">
            {program?.functions.map((func) => (
              <button
                key={func.name}
                className={func.name === selectedFunctionName ? "func-item active" : "func-item"}
                onClick={() => {
                  setSelectedFunctionName(func.name);
                  setSelectedBlockId(func.entry_block_id || func.blocks[0]?.id || "");
                  setSelectedInstructionAddress(func.blocks[0]?.instructions[0]?.address ?? null);
                }}
              >
                {func.name}
              </button>
            ))}
          </div>

          {selectedFunction ? (
            <CfgGraph
              func={selectedFunction}
              selectedBlockId={selectedBlockId}
              onSelectBlock={(blockId) => {
                setSelectedBlockId(blockId);
                const block = selectedFunction.blocks.find((item) => item.id === blockId);
                setSelectedInstructionAddress(block?.instructions[0]?.address ?? null);
              }}
            />
          ) : (
            <p className="placeholder">Analyze a sample to render CFG.</p>
          )}
        </aside>

        <section className="center-pane">
          {selectedFunction ? (
            <CodePanel
              func={selectedFunction}
              selectedBlockId={selectedBlockId}
              selectedInstructionAddress={selectedInstructionAddress}
              onSelectInstruction={setSelectedInstructionAddress}
            />
          ) : (
            <div className="panel">No function selected</div>
          )}
        </section>

        <aside className="right-pane">
          {selectedFunction ? (
            <StackPanel func={selectedFunction} selectedBlock={selectedBlock} selectedInstruction={selectedInstruction} />
          ) : (
            <div className="panel">No stack data</div>
          )}
        </aside>

        <section className="bottom-pane">
          <ExplanationPanel
            beginnerMode={beginnerMode}
            onToggleBeginnerMode={() => {
              const next = !beginnerMode;
              setBeginnerMode(next);
              void persistUIState(selectedFunctionName, selectedBlockId, next);
            }}
            instructionExplanation={instructionExplanation}
            blockExplanation={blockExplanation}
            pathExplanation={pathExplanation}
            functionExplanation={functionExplanation}
            projectState={projectState}
            onCreateAnnotation={async (text) => {
              const state = await createAnnotation(selectedProjectId, {
                target_type: activeTarget.type,
                target_id: activeTarget.id,
                text
              });
              setProjectState(state);
            }}
            onCreateBookmark={async (note) => {
              const state = await createBookmark(selectedProjectId, {
                target_type: activeTarget.type,
                target_id: activeTarget.id,
                note
              });
              setProjectState(state);
            }}
            onCreateRename={async (newName) => {
              const targetType = activeTarget.type === "function" ? "function" : "block";
              const targetId = activeTarget.type === "instruction" ? selectedBlockId || selectedFunctionName : activeTarget.id;
              const state = await createRename(selectedProjectId, {
                target_type: targetType,
                target_id: targetId,
                new_name: newName
              });
              setProjectState(state);
            }}
          />
        </section>
      </section>
    </main>
  );
}
