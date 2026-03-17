import { useEffect, useMemo, useState } from "react";

import { CfgGraph } from "./components/CfgGraph";
import { CodePanel } from "./components/CodePanel";
import { ExplanationPanel } from "./components/ExplanationPanel";
import { StackPanel } from "./components/StackPanel";
import {
  cancelTask,
  createAnalysisTask,
  createAnnotation,
  createBookmark,
  createConstraint,
  createProject,
  createRename,
  createTaskEventSource,
  discoverBinaries,
  fetchAnalysis,
  fetchConstraints,
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
import type {
  AnalysisConstraint,
  BinaryCandidate,
  EvidenceRef,
  Explanation,
  Func,
  Program,
  ProjectInfo,
  ProjectState,
  RuntimeInfo,
  SampleInfo,
  SampleRecord,
  TaskStatus
} from "./lib/types";
import "./styles/app.css";

type RoutePage = "workspace" | "analysis" | "explain";

function newSessionId() {
  return `session-${Date.now()}`;
}

function inSection(address: number, sectionVa: number, sectionSize: number): boolean {
  return address >= sectionVa && address < sectionVa + Math.max(1, sectionSize);
}

function routeFromHash(hash: string): RoutePage {
  const normalized = hash.replace(/^#\/?/, "").trim().toLowerCase();
  if (normalized === "analysis") {
    return "analysis";
  }
  if (normalized === "explain" || normalized === "explanation") {
    return "explain";
  }
  return "workspace";
}

function statusText(status: TaskStatus["status"]): string {
  switch (status) {
    case "queued":
      return "排队中";
    case "running":
      return "执行中";
    case "done":
      return "已完成";
    case "failed":
      return "失败";
    case "cancelled":
      return "已取消";
    default:
      return status;
  }
}

export default function App() {
  const [route, setRoute] = useState<RoutePage>(() => routeFromHash(window.location.hash));

  const [runtime, setRuntime] = useState<RuntimeInfo | null>(null);
  const [samples, setSamples] = useState<SampleInfo[]>([]);
  const [projects, setProjects] = useState<ProjectInfo[]>([]);
  const [selectedProjectId, setSelectedProjectId] = useState<string>("default");
  const [projectNameInput, setProjectNameInput] = useState<string>("我的项目");
  const [projectSamples, setProjectSamples] = useState<SampleRecord[]>([]);

  const [selectedSampleId, setSelectedSampleId] = useState<string>("demo_stack_branch");
  const [customBinaryPath, setCustomBinaryPath] = useState<string>("");
  const [binarySearch, setBinarySearch] = useState<string>("");
  const [binaryCandidates, setBinaryCandidates] = useState<BinaryCandidate[]>([]);
  const [binaryScannedRoots, setBinaryScannedRoots] = useState<string[]>([]);
  const [isDiscoveringBinaries, setIsDiscoveringBinaries] = useState<boolean>(false);

  const [sessionId, setSessionId] = useState<string>(newSessionId());
  const [taskStatus, setTaskStatus] = useState<TaskStatus | null>(null);
  const [activeTaskId, setActiveTaskId] = useState<string | null>(null);

  const [program, setProgram] = useState<Program | null>(null);
  const [selectedFunctionName, setSelectedFunctionName] = useState<string>("");
  const [selectedBlockId, setSelectedBlockId] = useState<string>("");
  const [selectedInstructionAddress, setSelectedInstructionAddress] = useState<number | null>(null);
  const [functionQuery, setFunctionQuery] = useState<string>("");
  const [importFilter, setImportFilter] = useState<string>("");
  const [stringFilter, setStringFilter] = useState<string>("");
  const [sectionFilter, setSectionFilter] = useState<string>("");

  const [instructionExplanation, setInstructionExplanation] = useState<Explanation | null>(null);
  const [blockExplanation, setBlockExplanation] = useState<Explanation | null>(null);
  const [pathExplanation, setPathExplanation] = useState<Explanation | null>(null);
  const [functionExplanation, setFunctionExplanation] = useState<Explanation | null>(null);
  const [projectState, setProjectState] = useState<ProjectState | null>(null);
  const [beginnerMode, setBeginnerMode] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [constraints, setConstraints] = useState<AnalysisConstraint[]>([]);
  const [showIRDebug, setShowIRDebug] = useState(false);

  useEffect(() => {
    const onHashChange = () => {
      setRoute(routeFromHash(window.location.hash));
    };
    if (!window.location.hash) {
      window.location.hash = "/workspace";
      onHashChange();
    }
    window.addEventListener("hashchange", onHashChange);
    return () => window.removeEventListener("hashchange", onHashChange);
  }, []);

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
        setError(`初始化失败: ${(e as Error).message}`);
      }
    })();
  }, []);

  const runBinaryDiscovery = async (query: string) => {
    setIsDiscoveringBinaries(true);
    try {
      const payload = await discoverBinaries({
        q: query,
        limit: 60,
        maxDepth: 5
      });
      setBinaryCandidates(payload.candidates);
      setBinaryScannedRoots(payload.scanned_roots);
    } catch (e) {
      setError(`扫描可分析程序失败: ${(e as Error).message}`);
    } finally {
      setIsDiscoveringBinaries(false);
    }
  };

  useEffect(() => {
    // Load once with default query so users can directly pick a binary.
    void runBinaryDiscovery("");
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
        const constraintPayload = await fetchConstraints(selectedProjectId);
        setConstraints(constraintPayload.constraints);
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
  const selectedFunctionXrefs = useMemo(
    () => (program?.xrefs ?? []).filter((item) => item.source_function === selectedFunctionName),
    [program, selectedFunctionName]
  );

  const filteredFunctions = useMemo(() => {
    const functions = program?.functions ?? [];
    const xrefs = program?.xrefs ?? [];
    const functionTerm = functionQuery.trim().toLowerCase();
    const importTerm = importFilter.trim().toLowerCase();
    const stringTerm = stringFilter.trim().toLowerCase();

    return functions.filter((fn) => {
      if (functionTerm && !fn.name.toLowerCase().includes(functionTerm)) {
        return false;
      }
      if (sectionFilter && program) {
        const section = program.sections.find((item) => item.name === sectionFilter);
        if (section && !inSection(fn.entry_address, section.va, section.virtual_size)) {
          return false;
        }
      }
      if (importTerm && program) {
        const hasImport = xrefs.some(
          (x) => x.source_function === fn.name && x.type === "import" && x.target_id.toLowerCase().includes(importTerm)
        );
        if (!hasImport) {
          return false;
        }
      }
      if (stringTerm && program) {
        const hasString = xrefs.some(
          (x) =>
            x.source_function === fn.name &&
            x.type === "string" &&
            (x.note.toLowerCase().includes(stringTerm) || x.target_id.toLowerCase().includes(stringTerm))
        );
        if (!hasString) {
          return false;
        }
      }
      return true;
    });
  }, [program, functionQuery, importFilter, stringFilter, sectionFilter]);

  useEffect(() => {
    if (!program) return;
    if (selectedFunctionName && filteredFunctions.some((item) => item.name === selectedFunctionName)) {
      return;
    }
    const first = filteredFunctions[0];
    if (first) {
      setSelectedFunctionName(first.name);
      setSelectedBlockId(first.entry_block_id || first.blocks[0]?.id || "");
      setSelectedInstructionAddress(first.blocks[0]?.instructions[0]?.address ?? null);
    }
  }, [program, filteredFunctions, selectedFunctionName]);

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
    setActiveTaskId(null);
    const firstFunction = payload.program.functions[0];
    const firstBlock = firstFunction?.entry_block_id || firstFunction?.blocks[0]?.id || "";
    const firstInstr = firstFunction?.blocks[0]?.instructions[0]?.address ?? null;

    setSelectedFunctionName(firstFunction?.name || "");
    setSelectedBlockId(firstBlock);
    setSelectedInstructionAddress(firstInstr);
    setFunctionQuery("");
    setImportFilter("");
    setStringFilter("");
    setSectionFilter("");

    await persistUIState(firstFunction?.name || "", firstBlock, beginnerMode);
    setProjectState(await fetchProjectState(selectedProjectId));
    setProjectSamples(await fetchProjectSamples(selectedProjectId));
  };

  const runSelectedSample = async () => {
    setError(null);
    const sid = newSessionId();
    setSessionId(sid);
    setTaskStatus(null);
    setActiveTaskId(null);

    const analyzePayload: {
      project_id: string;
      session_id: string;
      sample_id?: string;
      binary_path?: string;
    } = {
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
      setActiveTaskId(task_id);
      const source = createTaskEventSource(task_id);

      source.addEventListener("progress", (event) => {
        const update = JSON.parse((event as MessageEvent<string>).data) as TaskStatus;
        setTaskStatus(update);

        if (update.status === "done") {
          source.close();
          void fetchAndApplyAnalysis(sid);
        }
        if (update.status === "failed" || update.status === "cancelled") {
          source.close();
          setError(update.detail || "分析任务失败");
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
          if (current.status === "failed" || current.status === "cancelled") {
            setError(current.detail || "分析任务失败");
          }
        })();
      };
    } catch (e) {
      setError(`分析失败: ${(e as Error).message}`);
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

  const selectFunction = (func: Func) => {
    setSelectedFunctionName(func.name);
    setSelectedBlockId(func.entry_block_id || func.blocks[0]?.id || "");
    setSelectedInstructionAddress(func.blocks[0]?.instructions[0]?.address ?? null);
  };

  const handleEvidenceSelect = (evidence: EvidenceRef) => {
    if (!selectedFunction) return;
    const blockId = evidence.block_ids[0];
    if (blockId) {
      setSelectedBlockId(blockId);
      const block = selectedFunction.blocks.find((item) => item.id === blockId);
      setSelectedInstructionAddress(block?.instructions[0]?.address ?? null);
      return;
    }
    if (evidence.instruction_addresses.length > 0) {
      const addr = evidence.instruction_addresses[0];
      const block = selectedFunction.blocks.find((item) => item.instructions.some((inst) => inst.address === addr));
      if (block) {
        setSelectedBlockId(block.id);
      }
      setSelectedInstructionAddress(addr);
    }
  };

  const applyConstraint = async (constraint: AnalysisConstraint) => {
    const response = await createConstraint(selectedProjectId, constraint);
    setConstraints(response.constraints);
    await runSelectedSample();
  };

  const navigate = (next: RoutePage) => {
    window.location.hash = `/${next}`;
    setRoute(next);
  };

  const useDiscoveredBinary = (path: string) => {
    setCustomBinaryPath(path);
    navigate("workspace");
  };

  return (
    <main className="app-root">
      <header className="top-bar">
        <div>
          <h1>AI-DecompVis</h1>
          <p>
            运行模式: {runtime?.mode ?? "..."}
            {runtime?.daemon_target ? ` @ ${runtime.daemon_target}` : ""}
          </p>
        </div>

        <nav className="page-nav" aria-label="页面导航">
          <button className={route === "workspace" ? "nav-item active" : "nav-item"} onClick={() => navigate("workspace")}>
            工作区
          </button>
          <button className={route === "analysis" ? "nav-item active" : "nav-item"} onClick={() => navigate("analysis")}>
            函数分析
          </button>
          <button className={route === "explain" ? "nav-item active" : "nav-item"} onClick={() => navigate("explain")}>
            解释与标注
          </button>
        </nav>

        <div className="top-controls">
          <select value={selectedProjectId} onChange={(e) => setSelectedProjectId(e.target.value)}>
            <option value="default">default</option>
            {projects.map((project) => (
              <option key={project.project_id} value={project.project_id}>
                {project.project_id}
              </option>
            ))}
          </select>
          <input value={projectNameInput} onChange={(e) => setProjectNameInput(e.target.value)} placeholder="新项目名称" />
          <button
            onClick={async () => {
              const pid = `project-${Date.now()}`;
              const created = await createProject({ project_id: pid, name: projectNameInput || pid });
              const items = await fetchProjects();
              setProjects(items);
              setSelectedProjectId(created.project_id);
            }}
          >
            新建项目
          </button>
        </div>
      </header>

      {taskStatus ? (
        <div className="task-progress panel">
          <strong>
            任务状态: {statusText(taskStatus.status)} ({taskStatus.percent}%)
          </strong>
          <span>
            {taskStatus.stage} - {taskStatus.detail}
          </span>
          <div className="progress-bar">
            <div className="progress-fill" style={{ width: `${Math.max(0, Math.min(100, taskStatus.percent))}%` }} />
          </div>
          {activeTaskId && taskStatus.status === "running" ? (
            <button
              onClick={async () => {
                try {
                  const next = await cancelTask(activeTaskId);
                  setTaskStatus(next);
                } catch (e) {
                  setError(`取消任务失败: ${(e as Error).message}`);
                }
              }}
            >
              取消任务
            </button>
          ) : null}
        </div>
      ) : null}

      {error ? <div className="error-banner">{error}</div> : null}

      {route === "workspace" ? (
        <section className="page-grid workspace-grid">
          <aside className="panel route-panel-scroll">
            <h3>工作区与样本</h3>
            <div className="function-list">
              <select value={selectedSampleId} onChange={(e) => setSelectedSampleId(e.target.value)}>
                {samples.map((sample) => (
                  <option key={sample.sample_id} value={sample.sample_id}>
                    {sample.sample_id} ({sample.source_type})
                  </option>
                ))}
              </select>
              <button onClick={runSelectedSample}>开始分析</button>
            </div>
            <input
              value={customBinaryPath}
              onChange={(e) => setCustomBinaryPath(e.target.value)}
              placeholder="或输入本地二进制路径"
            />

            <div className="summary-list">
              <h4>自动扫描可反编译程序</h4>
              <div className="discover-toolbar">
                <input
                  value={binarySearch}
                  onChange={(e) => setBinarySearch(e.target.value)}
                  placeholder="按文件名/路径搜索，如 app 或 release"
                />
                <button onClick={() => void runBinaryDiscovery(binarySearch)} disabled={isDiscoveringBinaries}>
                  {isDiscoveringBinaries ? "扫描中..." : "刷新扫描"}
                </button>
              </div>
              <p className="discover-hint">
                当前运行于 WSL，可扫描 WSL 路径以及 `/mnt/*` 挂载盘。
              </p>
              <ul className="discover-list">
                {binaryCandidates.slice(0, 40).map((item) => (
                  <li key={item.path} className="discover-item">
                    <div className="discover-header">
                      <button className="linkish" onClick={() => useDiscoveredBinary(item.path)}>
                        {item.name}
                      </button>
                      <span className={`priority-badge ${item.priority_label}`}>
                        P{item.priority} / {item.priority_label}
                      </span>
                    </div>
                    <small className="discover-path">{item.path}</small>
                    <small className="discover-meta">
                      {Math.round(item.size_bytes / 1024)} KB · {item.modified_at}
                    </small>
                    <small className="discover-meta">{item.reasons.join(" / ")}</small>
                  </li>
                ))}
              </ul>
              {binaryCandidates.length === 0 ? <small className="discover-hint">未找到匹配程序</small> : null}
              {binaryScannedRoots.length > 0 ? (
                <small className="discover-hint">扫描根目录: {binaryScannedRoots.slice(0, 3).join(" | ")}</small>
              ) : null}
            </div>

            <div className="summary-list">
              <h4>程序概览</h4>
              <p>入口点: {program ? `0x${program.entry_point.toString(16)}` : "-"}</p>
              <p>函数数量: {program?.functions.length ?? 0}</p>
              <p>交叉引用: {program?.xrefs.length ?? 0}</p>
              <p>区段数: {program?.sections.length ?? 0}</p>
              <p>导入数: {program?.imports.length ?? 0}</p>
              <p>字符串数: {program?.strings.length ?? 0}</p>
            </div>

            <div className="summary-list">
              <h4>分析阶段（Stage/Maturity）</h4>
              <ul>
                {(program?.stages ?? []).map((stage) => (
                  <li key={`${stage.name}-${stage.detail}`}>
                    {stage.name}: {stage.status} ({Math.round(stage.confidence * 100)}%)
                  </li>
                ))}
              </ul>
            </div>

            <div className="summary-list">
              <h4>区段</h4>
              <ul>
                {(program?.sections ?? []).map((section) => (
                  <li key={section.name}>
                    {section.name} ({section.kind})
                  </li>
                ))}
              </ul>
            </div>

            <div className="summary-list">
              <h4>导入导航</h4>
              <ul>
                {(program?.imports ?? []).slice(0, 30).map((imp) => (
                  <li key={`${imp.dll}-${imp.name}-${imp.iat_va}`}>
                    <button
                      className="linkish"
                      onClick={() => {
                        setImportFilter(`${imp.dll}!${imp.name}`);
                        navigate("analysis");
                      }}
                    >
                      {imp.dll}!{imp.name}
                    </button>
                    <small> [{imp.category}]</small>
                  </li>
                ))}
              </ul>
            </div>

            <div className="summary-list">
              <h4>字符串导航</h4>
              <ul>
                {(program?.strings ?? []).slice(0, 30).map((item) => (
                  <li key={`${item.id}-${item.va}`}>
                    <button
                      className="linkish"
                      onClick={() => {
                        setStringFilter(item.value.slice(0, 16));
                        navigate("analysis");
                      }}
                    >
                      {item.value.slice(0, 32)}
                    </button>
                  </li>
                ))}
              </ul>
            </div>
          </aside>

          <section className="panel route-panel-scroll">
            <h3>函数浏览与过滤</h3>
            <div className="summary-list">
              <input value={functionQuery} onChange={(e) => setFunctionQuery(e.target.value)} placeholder="按函数名搜索" />
              <input value={importFilter} onChange={(e) => setImportFilter(e.target.value)} placeholder="按导入符号过滤" />
              <input value={stringFilter} onChange={(e) => setStringFilter(e.target.value)} placeholder="按字符串过滤" />
              <select value={sectionFilter} onChange={(e) => setSectionFilter(e.target.value)}>
                <option value="">全部区段</option>
                {(program?.sections ?? []).map((section) => (
                  <option key={section.name} value={section.name}>
                    {section.name}
                  </option>
                ))}
              </select>
            </div>

            <div className="function-list">
              {filteredFunctions.map((func) => (
                <button
                  key={func.name}
                  className={func.name === selectedFunctionName ? "func-item active" : "func-item"}
                  onClick={() => {
                    selectFunction(func);
                    navigate("analysis");
                  }}
                >
                  {func.name}
                </button>
              ))}
            </div>

            <div className="summary-list">
              <h4>最近样本</h4>
              <ul>
                {projectSamples.slice(0, 8).map((sample) => (
                  <li key={`${sample.sample_id}-${sample.created_at}`}>{sample.sample_id}</li>
                ))}
              </ul>
            </div>

            {selectedFunction ? (
              <div className="summary-list">
                <h4>当前函数元信息</h4>
                <p>调用约定: {selectedFunction.calling_convention_hint}</p>
                <p>
                  参数/局部变量: {selectedFunction.params_hint}/{selectedFunction.locals_hint}
                </p>
                <p>
                  调用者/被调者: {selectedFunction.callers.length}/{selectedFunction.callees.length}
                </p>
                <p>
                  置信度: {(selectedFunction.confidence * 100).toFixed(0)}% | 返回提示: {selectedFunction.summary.return_hint}
                </p>
                <p>
                  不返回函数: {selectedFunction.summary.no_return ? "是" : "否"} | 尾调用候选:{" "}
                  {selectedFunction.summary.tailcall_candidate ? "是" : "否"}
                </p>
              </div>
            ) : (
              <p className="placeholder">请先分析样本并选择函数。</p>
            )}
          </section>
        </section>
      ) : null}

      {route === "analysis" ? (
        <section className="layout-grid">
          <aside className="panel left-pane route-panel-scroll">
            <h3>函数与 CFG 导航</h3>
            <div className="summary-list">
              <input value={functionQuery} onChange={(e) => setFunctionQuery(e.target.value)} placeholder="按函数名搜索" />
              <input value={importFilter} onChange={(e) => setImportFilter(e.target.value)} placeholder="按导入符号过滤" />
              <input value={stringFilter} onChange={(e) => setStringFilter(e.target.value)} placeholder="按字符串过滤" />
            </div>

            <div className="function-list">
              {filteredFunctions.map((func) => (
                <button
                  key={func.name}
                  className={func.name === selectedFunctionName ? "func-item active" : "func-item"}
                  onClick={() => selectFunction(func)}
                >
                  {func.name}
                </button>
              ))}
            </div>

            <div className="summary-list">
              <h4>交叉引用</h4>
              <ul>
                {selectedFunctionXrefs.slice(0, 14).map((xref) => (
                  <li key={xref.id}>
                    <button
                      className="linkish"
                      onClick={() => {
                        if (xref.target_kind === "function") {
                          const fn = program?.functions.find((item) => item.name === xref.target_id);
                          if (fn) {
                            selectFunction(fn);
                            return;
                          }
                        }
                        const block = selectedFunction?.blocks.find((item) =>
                          item.instructions.some((inst) => inst.address === xref.source_address)
                        );
                        if (block) {
                          setSelectedBlockId(block.id);
                        }
                        setSelectedInstructionAddress(xref.source_address);
                      }}
                    >
                      {xref.type}: {xref.target_id}
                    </button>
                    <small> ({Math.round(xref.confidence * 100)}%)</small>
                  </li>
                ))}
              </ul>
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
              <p className="placeholder">先分析一个样本后才能展示 CFG。</p>
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
              <div className="panel">暂无函数，请先在工作区页面执行分析。</div>
            )}
          </section>

          <aside className="right-pane">
            {selectedFunction ? (
              <>
                <StackPanel func={selectedFunction} selectedBlock={selectedBlock} selectedInstruction={selectedInstruction} />
                <div className="panel ir-debug-panel">
                  <div className="explain-header">
                    <h3>IR / SSA 调试视图</h3>
                    <button onClick={() => setShowIRDebug((v) => !v)}>{showIRDebug ? "收起" : "展开"}</button>
                  </div>
                  <p>
                    IR 指令: {selectedFunction.ir.summary.instruction_count}, phi: {selectedFunction.ir.summary.phi_count},
                    MemorySSA 定义/使用/合流: {selectedFunction.ir.summary.memory_def_count}/
                    {selectedFunction.ir.summary.memory_use_count}/{selectedFunction.ir.summary.memory_phi_count}
                  </p>
                  <p>
                    switch 候选: {selectedFunction.ir.has_switch_candidate ? "是" : "否"} | 间接控制流:{" "}
                    {selectedFunction.ir.has_indirect_control ? "是" : "否"}
                  </p>
                  <p>
                    成熟度: {selectedFunction.summary.maturity} | this 指针线索:{" "}
                    {selectedFunction.summary.has_this_pointer ? "是" : "否"} | unwind:{" "}
                    {selectedFunction.summary.has_unwind ? "是" : "否"}
                  </p>
                  <h4>阶段状态</h4>
                  <ul>
                    {selectedFunction.stages.slice(0, 8).map((stage) => (
                      <li key={`${stage.name}-${stage.detail}`}>
                        {stage.name}: {stage.status} ({Math.round(stage.confidence * 100)}%) - {stage.detail}
                      </li>
                    ))}
                  </ul>
                  {showIRDebug ? (
                    <>
                      <h4>IR 基本块</h4>
                      <ul>
                        {selectedFunction.ir.blocks.slice(0, 8).map((block) => (
                          <li key={block.id}>
                            {block.id} (pred:{block.preds.length}, succ:{block.succs.length}, inst:{block.instructions.length})
                          </li>
                        ))}
                      </ul>
                      <h4>SSA 定义-使用</h4>
                      <ul>
                        {selectedFunction.ir.def_use.slice(0, 8).map((item) => (
                          <li key={item.value}>
                            {item.value} def:{item.def_inst_id || "-"} uses:{item.use_inst_ids.length}
                          </li>
                        ))}
                      </ul>
                      <h4>MemorySSA 节点</h4>
                      <ul>
                        {selectedFunction.ir.memory_ssa.slice(0, 10).map((item) => (
                          <li key={item.id}>
                            {item.kind} v{item.version} ({item.slot || item.block_id})
                          </li>
                        ))}
                      </ul>
                    </>
                  ) : null}
                </div>
              </>
            ) : (
              <div className="panel">暂无栈数据</div>
            )}
          </aside>

          <section className="bottom-pane panel">
            <h3>路径摘要与函数特征</h3>
            {selectedFunction ? (
              <>
                <p>
                  副作用: {selectedFunction.summary.side_effects.join(", ") || "-"} | 导入语义:{" "}
                  {selectedFunction.summary.imported_semantics.join(", ") || "-"}
                </p>
                <p>
                  间接目标候选: {selectedFunction.summary.possible_indirect_targets.join(", ") || "-"}
                </p>
                <p>
                  vtable 线索: {selectedFunction.summary.vtable_candidates.join(", ") || "-"} | ctor/dtor:{" "}
                  {selectedFunction.summary.ctor_like ? "ctor" : "-"} / {selectedFunction.summary.dtor_like ? "dtor" : "-"}
                </p>
                <p>
                  unwind 摘要: {selectedFunction.summary.unwind_summary || (selectedFunction.unwind.present ? "present" : "-")}
                </p>
                <ul>
                  {selectedFunction.path_summaries.slice(0, 8).map((item) => (
                    <li key={item.block_id}>{item.summary}</li>
                  ))}
                </ul>
              </>
            ) : (
              <p>暂无路径数据。</p>
            )}
          </section>
        </section>
      ) : null}

      {route === "explain" ? (
        <section className="page-grid explain-page-grid">
          <aside className="panel route-panel-scroll">
            <h3>解释目标选择</h3>
            <div className="summary-list">
              <h4>函数</h4>
              <div className="function-list">
                {filteredFunctions.map((func) => (
                  <button
                    key={func.name}
                    className={func.name === selectedFunctionName ? "func-item active" : "func-item"}
                    onClick={() => selectFunction(func)}
                  >
                    {func.name}
                  </button>
                ))}
              </div>
            </div>

            <div className="summary-list">
              <h4>基本块</h4>
              <ul>
                {(selectedFunction?.blocks ?? []).slice(0, 24).map((block) => (
                  <li key={block.id}>
                    <button
                      className="linkish"
                      onClick={() => {
                        setSelectedBlockId(block.id);
                        setSelectedInstructionAddress(block.instructions[0]?.address ?? null);
                      }}
                    >
                      {block.id}
                    </button>
                  </li>
                ))}
              </ul>
            </div>

            <div className="summary-list">
              <h4>指令</h4>
              <ul>
                {(selectedFunction?.blocks ?? [])
                  .flatMap((b) => b.instructions)
                  .slice(0, 40)
                  .map((inst) => (
                    <li key={inst.address}>
                      <button className="linkish" onClick={() => setSelectedInstructionAddress(inst.address)}>
                        0x{inst.address.toString(16)} {inst.text}
                      </button>
                    </li>
                  ))}
              </ul>
            </div>

            <div className="summary-list">
              <h4>用户约束 ({constraints.length})</h4>
              <button
                disabled={!selectedFunction}
                onClick={async () => {
                  if (!selectedFunction) return;
                  await applyConstraint({
                    id: `nr-${Date.now()}`,
                    kind: "no_return",
                    function_name: selectedFunction.name,
                    instruction_address: 0,
                    variable: "",
                    type_name: "",
                    value_text: "",
                    candidate_targets: [],
                    enabled: true
                  });
                }}
              >
                标记函数为不返回并重分析
              </button>
              <button
                disabled={!selectedInstruction}
                onClick={async () => {
                  if (!selectedInstruction) return;
                  const raw = window.prompt("请输入间接目标 VA（十六进制，如 0x140001050）");
                  if (!raw) return;
                  const parsed = Number.parseInt(raw, 16);
                  if (Number.isNaN(parsed)) {
                    setError("目标地址格式错误，请使用十六进制。");
                    return;
                  }
                  await applyConstraint({
                    id: `it-${Date.now()}`,
                    kind: "indirect_target",
                    function_name: selectedFunction?.name ?? "",
                    instruction_address: selectedInstruction.address,
                    variable: "",
                    type_name: "",
                    value_text: "",
                    candidate_targets: [parsed],
                    enabled: true
                  });
                }}
              >
                添加间接目标并重分析
              </button>
              <button
                disabled={!selectedFunction}
                onClick={async () => {
                  if (!selectedFunction) return;
                  const variable = window.prompt("请输入变量/寄存器名（如 edi / rcx / arg_0）");
                  if (!variable) return;
                  const range = window.prompt("请输入取值范围（如 0..2 或 5）");
                  if (!range) return;
                  await applyConstraint({
                    id: `vr-${Date.now()}`,
                    kind: "value_range",
                    function_name: selectedFunction.name,
                    instruction_address: selectedInstruction?.address ?? 0,
                    variable: variable.trim(),
                    type_name: "",
                    value_text: range.trim(),
                    candidate_targets: [],
                    enabled: true
                  });
                }}
              >
                添加取值范围约束并重分析
              </button>
              <button
                disabled={!selectedFunction}
                onClick={async () => {
                  if (!selectedFunction) return;
                  const variable = window.prompt("请输入变量名（如 local_1 / arg_0）");
                  if (!variable) return;
                  const typeName = window.prompt("请输入类型（如 int32_t / char* / MyStruct*）");
                  if (!typeName) return;
                  await applyConstraint({
                    id: `to-${Date.now()}`,
                    kind: "type_override",
                    function_name: selectedFunction.name,
                    instruction_address: 0,
                    variable: variable.trim(),
                    type_name: typeName.trim(),
                    value_text: "",
                    candidate_targets: [],
                    enabled: true
                  });
                }}
              >
                添加类型覆盖并重分析
              </button>
              <button
                disabled={!selectedFunction}
                onClick={async () => {
                  if (!selectedFunction) return;
                  const typeName = window.prompt("请输入 this 指针类型（可选，如 MyClass*）") ?? "";
                  await applyConstraint({
                    id: `tp-${Date.now()}`,
                    kind: "this_pointer",
                    function_name: selectedFunction.name,
                    instruction_address: 0,
                    variable: "rcx",
                    type_name: typeName.trim(),
                    value_text: "",
                    candidate_targets: [],
                    enabled: true
                  });
                }}
              >
                添加 this 指针提示并重分析
              </button>
              <ul>
                {constraints.slice(-8).map((item) => (
                  <li key={item.id || `${item.kind}-${item.function_name}-${item.instruction_address}`}>
                    {item.kind} {item.function_name ? `@${item.function_name}` : ""}{" "}
                    {item.variable ? `${item.variable}=${item.value_text || item.type_name}` : ""}
                  </li>
                ))}
              </ul>
            </div>
          </aside>

          <section>
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
              onSelectEvidence={handleEvidenceSelect}
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
                const state = await createRename(selectedProjectId, {
                  target_type: activeTarget.type === "instruction" ? "block" : activeTarget.type,
                  target_id: activeTarget.id,
                  new_name: newName
                });
                setProjectState(state);
              }}
            />
          </section>

          <aside className="panel route-panel-scroll">
            <h3>证据联动与元信息</h3>
            <p>当前函数: {selectedFunction?.name ?? "-"}</p>
            <p>当前块: {selectedBlockId || "-"}</p>
            <p>当前指令: {selectedInstructionAddress ? `0x${selectedInstructionAddress.toString(16)}` : "-"}</p>

            {selectedFunction ? (
              <>
                <div className="summary-list">
                  <h4>函数元信息</h4>
                  <p>调用约定: {selectedFunction.calling_convention_hint}</p>
                  <p>
                    置信度: {(selectedFunction.confidence * 100).toFixed(0)}% | 返回提示: {selectedFunction.summary.return_hint}
                  </p>
                  <p>
                    xref 入/出: {selectedFunction.xref_in_count}/{selectedFunction.xref_out_count}
                  </p>
                </div>

                <div className="summary-list">
                  <h4>调用链</h4>
                  <p>调用者: {selectedFunction.callers.join(", ") || "-"}</p>
                  <p>被调者: {selectedFunction.callees.join(", ") || "-"}</p>
                </div>

                <div className="summary-list">
                  <h4>路径摘要</h4>
                  <ul>
                    {selectedFunction.path_summaries.slice(0, 8).map((item) => (
                      <li key={item.block_id}>{item.summary}</li>
                    ))}
                  </ul>
                </div>
              </>
            ) : (
              <p>暂无可展示信息。</p>
            )}
          </aside>
        </section>
      ) : null}
    </main>
  );
}
