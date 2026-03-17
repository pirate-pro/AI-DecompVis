import * as vscode from "vscode";

type Program = {
  functions: Array<{
    name: string;
    blocks: Array<{ id: string; instructions: Array<{ address: number; text: string }> }>;
    calling_convention_hint: string;
    confidence: number;
    callers: string[];
    callees: string[];
    xref_in_count: number;
    xref_out_count: number;
    import_xref_count: number;
    string_xref_count: number;
    path_summaries: Array<{ block_id: string; summary: string }>;
    summary?: { return_hint: string; no_return: boolean; tailcall_candidate: boolean };
  }>;
  sections: Array<{ name: string; kind: string }>;
  imports: Array<{ dll: string; name: string; category: string }>;
  strings: Array<{ id: string; value: string }>;
  entry_point: number;
};

type ProjectInfo = {
  project_id: string;
  name: string;
  created_at: string;
};

type SessionRecord = {
  session_id: string;
  project_id: string;
  sample_id: string;
  created_at: string;
};

type Explanation = {
  id: string;
  level: string;
  confidence: number;
  low_confidence: boolean;
  low_confidence_reason: string;
  text: string;
  evidence_refs: Array<{
    id: string;
    summary: string;
    evidence_type: string;
    confidence: number;
    instruction_addresses: number[];
    block_ids: string[];
    unsupported_reason: string;
  }>;
};

class FunctionItem extends vscode.TreeItem {
  constructor(public readonly fnName: string) {
    super(fnName, vscode.TreeItemCollapsibleState.None);
    this.command = {
      command: "aidecompvis.showFunctionSummary",
      title: "Show Function Summary",
      arguments: [fnName]
    };
  }
}

class FunctionProvider implements vscode.TreeDataProvider<FunctionItem> {
  private _onDidChangeTreeData = new vscode.EventEmitter<void>();
  readonly onDidChangeTreeData = this._onDidChangeTreeData.event;

  private program: Program | null = null;
  private filterText = "";

  setProgram(program: Program | null) {
    this.program = program;
    this._onDidChangeTreeData.fire();
  }

  setFilter(text: string) {
    this.filterText = text.trim().toLowerCase();
    this._onDidChangeTreeData.fire();
  }

  getTreeItem(element: FunctionItem): vscode.TreeItem {
    return element;
  }

  getChildren(): Thenable<FunctionItem[]> {
    if (!this.program) return Promise.resolve([]);
    const names = this.program.functions
      .map((fn) => fn.name)
      .filter((name) => (this.filterText ? name.toLowerCase().includes(this.filterText) : true));
    return Promise.resolve(names.map((name) => new FunctionItem(name)));
  }
}

let cachedProgram: Program | null = null;
let cachedSessionId = "";
let cachedProjectId = "default";

async function fetchJson<T>(url: string, init?: RequestInit): Promise<T> {
  const response = await fetch(url, {
    headers: { "Content-Type": "application/json" },
    ...init
  });
  if (!response.ok) {
    throw new Error(await response.text());
  }
  return (await response.json()) as T;
}

function backendUrl(): string {
  return vscode.workspace.getConfiguration("aidecompvis").get<string>("backendUrl", "http://127.0.0.1:8000");
}

function requireSession(): { program: Program; sessionId: string; projectId: string } | null {
  if (!cachedProgram || !cachedSessionId) {
    vscode.window.showWarningMessage("No session connected. Run 'AI-DecompVis: Select Project Session' first.");
    return null;
  }
  return { program: cachedProgram, sessionId: cachedSessionId, projectId: cachedProjectId };
}

async function chooseFunction(program: Program, hinted?: string): Promise<string | undefined> {
  return (
    hinted ??
    (await vscode.window.showQuickPick(
      program.functions.map((fn) => fn.name),
      { title: "Select function" }
    ))
  );
}

async function refreshSession(sessionId: string, provider: FunctionProvider): Promise<void> {
  const payload = await fetchJson<{ session_id: string; project_id: string; program: Program }>(
    `${backendUrl()}/analysis/${sessionId}`
  );
  cachedProgram = payload.program;
  cachedSessionId = payload.session_id;
  cachedProjectId = payload.project_id || cachedProjectId;
  provider.setProgram(cachedProgram);
}

function renderFunctionHtml(functionName: string, fn: Program["functions"][number], program: Program, sessionId: string): string {
  return `
    <html>
      <body style="font-family: sans-serif; padding: 12px;">
        <h2>${functionName}</h2>
        <p><strong>Session:</strong> ${sessionId}</p>
        <p><strong>Calling Convention:</strong> ${fn.calling_convention_hint}</p>
        <p><strong>Confidence:</strong> ${(fn.confidence * 100).toFixed(0)}%</p>
        <p><strong>Blocks:</strong> ${fn.blocks.length}</p>
        <p><strong>Callers/Callees:</strong> ${fn.callers.length}/${fn.callees.length}</p>
        <p><strong>Xrefs In/Out:</strong> ${fn.xref_in_count}/${fn.xref_out_count}</p>
        <p><strong>Import/String Xrefs:</strong> ${fn.import_xref_count}/${fn.string_xref_count}</p>
        <p><strong>Return Hint:</strong> ${fn.summary?.return_hint ?? "unknown"}</p>
        <p><strong>No-Return:</strong> ${fn.summary?.no_return ? "yes" : "no"}</p>
        <p><strong>Tailcall Candidate:</strong> ${fn.summary?.tailcall_candidate ? "yes" : "no"}</p>
        <h3>Path Summary</h3>
        <ul>${fn.path_summaries.slice(0, 8).map((x) => `<li>${x.summary}</li>`).join("")}</ul>
        <h3>Program Summary</h3>
        <p>Sections: ${program.sections.length}</p>
        <p>Imports: ${program.imports.length}</p>
        <p>Strings: ${program.strings.length}</p>
        <p>Entry: 0x${program.entry_point.toString(16)}</p>
      </body>
    </html>
  `;
}

async function applyConstraintAndReanalyze(
  projectId: string,
  sessionId: string,
  constraint: unknown,
  provider: FunctionProvider
): Promise<void> {
  await fetchJson(`${backendUrl()}/projects/${projectId}/constraints`, {
    method: "POST",
    body: JSON.stringify({ constraint })
  });

  const sessions = await fetchJson<SessionRecord[]>(`${backendUrl()}/projects/${projectId}/sessions`);
  const currentSession = sessions.find((item) => item.session_id === sessionId);
  if (!currentSession) {
    throw new Error("current session not found in project");
  }

  await fetchJson(`${backendUrl()}/analysis/run`, {
    method: "POST",
    body: JSON.stringify({
      project_id: projectId,
      session_id: sessionId,
      sample_id: currentSession.sample_id
    })
  });

  await refreshSession(sessionId, provider);
}

export function activate(context: vscode.ExtensionContext) {
  const provider = new FunctionProvider();
  vscode.window.registerTreeDataProvider("aidecompvis.functions", provider);

  context.subscriptions.push(
    vscode.commands.registerCommand("aidecompvis.connectSession", async () => {
      const session = await vscode.window.showInputBox({
        title: "AI-DecompVis Session ID",
        placeHolder: "example: session-1700000000"
      });
      if (!session) return;

      try {
        await refreshSession(session, provider);
        vscode.window.showInformationMessage(`Connected AI-DecompVis session: ${session}`);
      } catch (err) {
        vscode.window.showErrorMessage(`Failed to connect session: ${(err as Error).message}`);
      }
    }),

    vscode.commands.registerCommand("aidecompvis.selectProjectSession", async () => {
      try {
        const projects = await fetchJson<ProjectInfo[]>(`${backendUrl()}/projects`);
        if (!projects.length) {
          vscode.window.showWarningMessage("No projects found. Run analysis in Web/Desktop first.");
          return;
        }
        const project = await vscode.window.showQuickPick(
          projects.map((item) => ({
            label: item.project_id,
            description: item.name
          })),
          { title: "Select AI-DecompVis project" }
        );
        if (!project) return;

        const sessions = await fetchJson<SessionRecord[]>(`${backendUrl()}/projects/${project.label}/sessions`);
        if (!sessions.length) {
          vscode.window.showWarningMessage("No sessions in selected project.");
          return;
        }
        const session = await vscode.window.showQuickPick(
          sessions.map((item) => ({
            label: item.session_id,
            description: `${item.sample_id} @ ${item.created_at}`
          })),
          { title: "Select AI-DecompVis session" }
        );
        if (!session) return;

        await refreshSession(session.label, provider);
        vscode.window.showInformationMessage(`Connected ${cachedProjectId}/${cachedSessionId}`);
      } catch (err) {
        vscode.window.showErrorMessage(`Failed to select session: ${(err as Error).message}`);
      }
    }),

    vscode.commands.registerCommand("aidecompvis.searchFunction", async () => {
      const term = await vscode.window.showInputBox({
        title: "Filter function list",
        placeHolder: "substring"
      });
      provider.setFilter(term ?? "");
    }),

    vscode.commands.registerCommand("aidecompvis.showFunctionSummary", async (fnName?: string) => {
      const current = requireSession();
      if (!current) return;

      const functionName = await chooseFunction(current.program, fnName);
      if (!functionName) return;
      const fn = current.program.functions.find((item) => item.name === functionName);
      if (!fn) return;

      const panel = vscode.window.createWebviewPanel(
        "aidecompvisFunction",
        `AI-DecompVis: ${functionName}`,
        vscode.ViewColumn.Beside,
        {}
      );
      panel.webview.html = renderFunctionHtml(functionName, fn, current.program, current.sessionId);
    }),

    vscode.commands.registerCommand("aidecompvis.showExplanation", async () => {
      const current = requireSession();
      if (!current) return;
      const functionName = await chooseFunction(current.program);
      if (!functionName) return;
      const fn = current.program.functions.find((item) => item.name === functionName);
      if (!fn) return;

      const level = await vscode.window.showQuickPick(["instruction", "block", "function", "path"], {
        title: "Select explanation level"
      });
      if (!level) return;

      let targetId = functionName;
      if (level === "block" || level === "path") {
        const block = await vscode.window.showQuickPick(fn.blocks.map((item) => item.id), {
          title: `Select target block for ${level}`
        });
        if (!block) return;
        targetId = block;
      }
      if (level === "instruction") {
        const choices = fn.blocks
          .flatMap((block) =>
            block.instructions.map((inst) => ({
              label: `0x${inst.address.toString(16)} ${inst.text}`,
              target: `0x${inst.address.toString(16)}`
            }))
          )
          .slice(0, 200);
        const inst = await vscode.window.showQuickPick(choices, { title: "Select instruction" });
        if (!inst) return;
        targetId = inst.target;
      }

      try {
        const payload = await fetchJson<{ explanation: Explanation }>(`${backendUrl()}/explanations`, {
          method: "POST",
          body: JSON.stringify({
            session_id: current.sessionId,
            function_name: functionName,
            level,
            target_id: targetId,
            beginner_mode: false
          })
        });

        const panel = vscode.window.createWebviewPanel(
          "aidecompvisExplanation",
          `AI-DecompVis Explanation (${level})`,
          vscode.ViewColumn.Beside,
          {}
        );
        const exp = payload.explanation;
        panel.webview.html = `
          <html>
            <body style="font-family: sans-serif; padding: 12px;">
              <h2>${functionName} / ${level} / ${targetId}</h2>
              <p><strong>confidence:</strong> ${(exp.confidence * 100).toFixed(0)}%</p>
              ${exp.low_confidence ? `<p><strong>low-confidence:</strong> ${exp.low_confidence_reason}</p>` : ""}
              <p>${exp.text}</p>
              <h3>Evidence</h3>
              <ul>
                ${exp.evidence_refs
                  .slice(0, 12)
                  .map(
                    (ev) =>
                      `<li><strong>${ev.id}</strong> [${ev.evidence_type} ${(ev.confidence * 100).toFixed(
                        0
                      )}%] - ${ev.summary}${ev.unsupported_reason ? ` (unsupported: ${ev.unsupported_reason})` : ""}</li>`
                  )
                  .join("")}
              </ul>
            </body>
          </html>
        `;
      } catch (err) {
        vscode.window.showErrorMessage(`Failed to get explanation: ${(err as Error).message}`);
      }
    }),

    vscode.commands.registerCommand("aidecompvis.addAnnotation", async () => {
      const current = requireSession();
      if (!current) return;
      const functionName = await chooseFunction(current.program);
      if (!functionName) return;
      const text = await vscode.window.showInputBox({
        title: "Annotation text",
        placeHolder: "what this function does"
      });
      if (!text?.trim()) return;

      try {
        await fetchJson(`${backendUrl()}/projects/${current.projectId}/annotations`, {
          method: "POST",
          body: JSON.stringify({
            target_type: "function",
            target_id: functionName,
            text: text.trim()
          })
        });
        vscode.window.showInformationMessage(`Annotation saved for ${functionName}`);
      } catch (err) {
        vscode.window.showErrorMessage(`Failed to save annotation: ${(err as Error).message}`);
      }
    }),

    vscode.commands.registerCommand("aidecompvis.addBookmark", async () => {
      const current = requireSession();
      if (!current) return;
      const functionName = await chooseFunction(current.program);
      if (!functionName) return;
      const note = await vscode.window.showInputBox({
        title: "Bookmark note",
        placeHolder: "why this function is important"
      });
      if (!note?.trim()) return;

      try {
        await fetchJson(`${backendUrl()}/projects/${current.projectId}/bookmarks`, {
          method: "POST",
          body: JSON.stringify({
            target_type: "function",
            target_id: functionName,
            note: note.trim()
          })
        });
        vscode.window.showInformationMessage(`Bookmark saved for ${functionName}`);
      } catch (err) {
        vscode.window.showErrorMessage(`Failed to save bookmark: ${(err as Error).message}`);
      }
    }),

    vscode.commands.registerCommand("aidecompvis.applyNoReturnConstraint", async () => {
      const current = requireSession();
      if (!current) return;
      const functionName = await chooseFunction(current.program);
      if (!functionName) return;

      try {
        await applyConstraintAndReanalyze(
          current.projectId,
          current.sessionId,
          {
            id: `vscode-nr-${Date.now()}`,
            kind: "no_return",
            function_name: functionName,
            instruction_address: 0,
            variable: "",
            type_name: "",
            value_text: "",
            candidate_targets: [],
            enabled: true
          },
          provider
        );
        vscode.window.showInformationMessage(
          `Applied no-return constraint to ${functionName} and refreshed session ${current.sessionId}`
        );
      } catch (err) {
        vscode.window.showErrorMessage(`Failed to apply no-return constraint: ${(err as Error).message}`);
      }
    }),

    vscode.commands.registerCommand("aidecompvis.applyValueRangeConstraint", async () => {
      const current = requireSession();
      if (!current) return;
      const functionName = await chooseFunction(current.program);
      if (!functionName) return;

      const variable = await vscode.window.showInputBox({
        title: "Value Range Constraint",
        placeHolder: "register/variable, e.g. edi or arg_0"
      });
      if (!variable?.trim()) return;
      const range = await vscode.window.showInputBox({
        title: "Range Expression",
        placeHolder: "e.g. 0..2 or 5"
      });
      if (!range?.trim()) return;

      try {
        await applyConstraintAndReanalyze(
          current.projectId,
          current.sessionId,
          {
            id: `vscode-vr-${Date.now()}`,
            kind: "value_range",
            function_name: functionName,
            instruction_address: 0,
            variable: variable.trim(),
            type_name: "",
            value_text: range.trim(),
            candidate_targets: [],
            enabled: true
          },
          provider
        );
        vscode.window.showInformationMessage(
          `Applied value_range(${variable}=${range}) to ${functionName} and refreshed ${current.sessionId}`
        );
      } catch (err) {
        vscode.window.showErrorMessage(`Failed to apply value range constraint: ${(err as Error).message}`);
      }
    }),

    vscode.commands.registerCommand("aidecompvis.applyTypeOverrideConstraint", async () => {
      const current = requireSession();
      if (!current) return;
      const functionName = await chooseFunction(current.program);
      if (!functionName) return;

      const variable = await vscode.window.showInputBox({
        title: "Type Override Constraint",
        placeHolder: "variable name, e.g. local_1 or arg_0"
      });
      if (!variable?.trim()) return;
      const typeName = await vscode.window.showInputBox({
        title: "Type Name",
        placeHolder: "e.g. int32_t / char* / MyClass*"
      });
      if (!typeName?.trim()) return;

      try {
        await applyConstraintAndReanalyze(
          current.projectId,
          current.sessionId,
          {
            id: `vscode-to-${Date.now()}`,
            kind: "type_override",
            function_name: functionName,
            instruction_address: 0,
            variable: variable.trim(),
            type_name: typeName.trim(),
            value_text: "",
            candidate_targets: [],
            enabled: true
          },
          provider
        );
        vscode.window.showInformationMessage(
          `Applied type_override(${variable}->${typeName}) to ${functionName} and refreshed ${current.sessionId}`
        );
      } catch (err) {
        vscode.window.showErrorMessage(`Failed to apply type override constraint: ${(err as Error).message}`);
      }
    })
  );
}

export function deactivate() {}
