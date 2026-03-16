const { contextBridge, ipcRenderer } = require("electron");

contextBridge.exposeInMainWorld("aidecompDesktop", {
  pickBinary: () => ipcRenderer.invoke("aidecompvis:pickBinary"),
  backendUrl: () => ipcRenderer.invoke("aidecompvis:backendUrl")
});
