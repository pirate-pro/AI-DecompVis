import type {
  Explanation,
  Program,
  ProjectInfo,
  ProjectState,
  RuntimeInfo,
  SampleInfo,
  SampleRecord,
  TaskStatus,
  UIState
} from "./types";

const BASE = import.meta.env.VITE_API_BASE ?? "/api";

async function jsonFetch<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(`${BASE}${path}`, {
    headers: {
      "Content-Type": "application/json",
      ...(init?.headers ?? {})
    },
    ...init
  });
  if (!response.ok) {
    const text = await response.text();
    throw new Error(text || `request failed: ${response.status}`);
  }
  return (await response.json()) as T;
}

export async function fetchRuntime(): Promise<RuntimeInfo> {
  return jsonFetch<RuntimeInfo>("/runtime");
}

export async function fetchSamples(): Promise<SampleInfo[]> {
  return jsonFetch<SampleInfo[]>("/samples");
}

export async function runAnalysis(payload: {
  project_id: string;
  session_id: string;
  sample_id?: string;
  binary_path?: string;
}): Promise<{ session_id: string; project_id: string; program: Program }> {
  return jsonFetch<{ session_id: string; project_id: string; program: Program }>("/analysis/run", {
    method: "POST",
    body: JSON.stringify(payload)
  });
}

export async function fetchAnalysis(sessionId: string): Promise<{ session_id: string; project_id: string; program: Program }> {
  return jsonFetch<{ session_id: string; project_id: string; program: Program }>(`/analysis/${sessionId}`);
}

export async function createAnalysisTask(payload: {
  analyze: {
    project_id: string;
    session_id: string;
    sample_id?: string;
    binary_path?: string;
  };
}): Promise<{ task_id: string }> {
  return jsonFetch<{ task_id: string }>("/analysis/tasks", {
    method: "POST",
    body: JSON.stringify(payload)
  });
}

export async function getTaskStatus(taskId: string): Promise<TaskStatus> {
  return jsonFetch<TaskStatus>(`/analysis/tasks/${taskId}`);
}

export function createTaskEventSource(taskId: string): EventSource {
  return new EventSource(`${BASE}/analysis/tasks/${taskId}/events`);
}

export async function fetchExplanation(payload: {
  session_id: string;
  function_name: string;
  level: "instruction" | "block" | "function" | "path";
  target_id: string;
  beginner_mode: boolean;
}): Promise<Explanation> {
  const res = await jsonFetch<{ explanation: Explanation }>("/explanations", {
    method: "POST",
    body: JSON.stringify(payload)
  });
  return res.explanation;
}

export async function createAnnotation(
  projectId: string,
  payload: { target_type: "instruction" | "block" | "function"; target_id: string; text: string }
): Promise<ProjectState> {
  return jsonFetch<ProjectState>(`/projects/${projectId}/annotations`, {
    method: "POST",
    body: JSON.stringify(payload)
  });
}

export async function createBookmark(
  projectId: string,
  payload: { target_type: "instruction" | "block" | "function"; target_id: string; note: string }
): Promise<ProjectState> {
  return jsonFetch<ProjectState>(`/projects/${projectId}/bookmarks`, {
    method: "POST",
    body: JSON.stringify(payload)
  });
}

export async function createRename(
  projectId: string,
  payload: { target_type: "function" | "block" | "variable"; target_id: string; new_name: string }
): Promise<ProjectState> {
  return jsonFetch<ProjectState>(`/projects/${projectId}/renames`, {
    method: "POST",
    body: JSON.stringify(payload)
  });
}

export async function fetchProjectState(projectId: string): Promise<ProjectState> {
  return jsonFetch<ProjectState>(`/projects/${projectId}/state`);
}

export async function createProject(payload: { project_id: string; name: string }): Promise<ProjectInfo> {
  return jsonFetch<ProjectInfo>("/projects", {
    method: "POST",
    body: JSON.stringify(payload)
  });
}

export async function fetchProjects(): Promise<ProjectInfo[]> {
  return jsonFetch<ProjectInfo[]>("/projects");
}

export async function deleteProject(projectId: string): Promise<{ status: string; project_id: string }> {
  return jsonFetch<{ status: string; project_id: string }>(`/projects/${projectId}`, { method: "DELETE" });
}

export async function fetchProjectSamples(projectId: string): Promise<SampleRecord[]> {
  return jsonFetch<SampleRecord[]>(`/projects/${projectId}/samples`);
}

export async function fetchUIState(projectId: string): Promise<UIState> {
  return jsonFetch<UIState>(`/projects/${projectId}/ui-state`);
}

export async function saveUIState(projectId: string, state: UIState): Promise<UIState> {
  return jsonFetch<UIState>(`/projects/${projectId}/ui-state`, {
    method: "POST",
    body: JSON.stringify(state)
  });
}
