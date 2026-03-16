import * as vscode from "vscode";

type Program = {
  functions: Array<{
    name: string;
    blocks: Array<{ id: string }>;
    calling_convention_hint: string;
    callers: string[];
    callees: string[];
    path_summaries: Array<{ summary: string }>;
  }>;
  sections: Array<{ name: string; kind: string }>;
  imports: Array<{ dll: string; name: string }>;
  strings: Array<{ value: string }>;
  entry_point: number;
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

  setProgram(program: Program | null) {
    this.program = program;
    this._onDidChangeTreeData.fire();
  }

  getTreeItem(element: FunctionItem): vscode.TreeItem {
    return element;
  }

  getChildren(): Thenable<FunctionItem[]> {
    if (!this.program) return Promise.resolve([]);
    return Promise.resolve(this.program.functions.map((fn) => new FunctionItem(fn.name)));
  }
}

let cachedProgram: Program | null = null;
let cachedSessionId = "";

async function fetchJson<T>(url: string): Promise<T> {
  const response = await fetch(url);
  if (!response.ok) {
    throw new Error(await response.text());
  }
  return (await response.json()) as T;
}

function backendUrl(): string {
  return vscode.workspace.getConfiguration("aidecompvis").get<string>("backendUrl", "http://127.0.0.1:8000");
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
        const payload = await fetchJson<{ session_id: string; program: Program }>(`${backendUrl()}/analysis/${session}`);
        cachedProgram = payload.program;
        cachedSessionId = session;
        provider.setProgram(cachedProgram);
        vscode.window.showInformationMessage(`Connected AI-DecompVis session: ${session}`);
      } catch (err) {
        vscode.window.showErrorMessage(`Failed to connect session: ${(err as Error).message}`);
      }
    }),

    vscode.commands.registerCommand("aidecompvis.showFunctionSummary", async (fnName?: string) => {
      if (!cachedProgram) {
        vscode.window.showWarningMessage("No session connected. Run 'AI-DecompVis: Connect Session' first.");
        return;
      }

      const functionName =
        fnName ??
        (await vscode.window.showQuickPick(cachedProgram.functions.map((fn) => fn.name), {
          title: "Select function"
        }));
      if (!functionName) return;

      const fn = cachedProgram.functions.find((item) => item.name === functionName);
      if (!fn) return;

      const panel = vscode.window.createWebviewPanel(
        "aidecompvisFunction",
        `AI-DecompVis: ${functionName}`,
        vscode.ViewColumn.Beside,
        {}
      );

      panel.webview.html = `
        <html>
          <body style="font-family: sans-serif; padding: 12px;">
            <h2>${functionName}</h2>
            <p><strong>Session:</strong> ${cachedSessionId}</p>
            <p><strong>Calling Convention:</strong> ${fn.calling_convention_hint}</p>
            <p><strong>Blocks:</strong> ${fn.blocks.length}</p>
            <p><strong>Callers/Callees:</strong> ${fn.callers.length}/${fn.callees.length}</p>
            <h3>Path Summary</h3>
            <ul>${fn.path_summaries.slice(0, 5).map((x) => `<li>${x.summary}</li>`).join("")}</ul>
            <h3>Program Summary</h3>
            <p>Sections: ${cachedProgram.sections.length}</p>
            <p>Imports: ${cachedProgram.imports.length}</p>
            <p>Strings: ${cachedProgram.strings.length}</p>
            <p>Entry: 0x${cachedProgram.entry_point.toString(16)}</p>
          </body>
        </html>
      `;
    })
  );
}

export function deactivate() {}
