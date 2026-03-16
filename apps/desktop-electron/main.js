const { app, BrowserWindow, dialog, ipcMain } = require("electron");
const { spawn } = require("node:child_process");
const path = require("node:path");

let backendProcess = null;

function startBackend() {
  if (backendProcess) return;

  const root = path.resolve(__dirname, "../..");
  const uvicorn = path.join(root, ".venv", "bin", "uvicorn");
  const env = {
    ...process.env,
    AIDECOMP_RUNTIME_MODE: process.env.AIDECOMP_RUNTIME_MODE || "embedded",
    PYTHONPATH: `${path.join(root, "core/aidecomp_py/python")}:${path.join(root, "services/aidecomp_api")}`
  };

  backendProcess = spawn(
    uvicorn,
    ["aidecomp_api.main:app", "--app-dir", path.join(root, "services/aidecomp_api"), "--host", "127.0.0.1", "--port", "8000"],
    { env, stdio: "inherit" }
  );

  backendProcess.on("exit", () => {
    backendProcess = null;
  });
}

function createWindow() {
  const win = new BrowserWindow({
    width: 1440,
    height: 920,
    webPreferences: {
      preload: path.join(__dirname, "preload.js")
    }
  });

  const webUrl = process.env.AIDECOMP_WEB_URL || "http://127.0.0.1:5173";
  win.loadURL(webUrl).catch(() => {
    win.loadFile(path.join(__dirname, "renderer/index.html"));
  });
}

app.whenReady().then(() => {
  startBackend();
  createWindow();

  ipcMain.handle("aidecompvis:pickBinary", async () => {
    const result = await dialog.showOpenDialog({
      properties: ["openFile"],
      filters: [{ name: "PE Executable", extensions: ["exe", "dll"] }, { name: "All Files", extensions: ["*"] }]
    });
    return result.canceled ? null : result.filePaths[0];
  });

  ipcMain.handle("aidecompvis:backendUrl", () => "http://127.0.0.1:8000");
});

app.on("window-all-closed", () => {
  if (backendProcess) {
    backendProcess.kill("SIGTERM");
  }
  if (process.platform !== "darwin") {
    app.quit();
  }
});
