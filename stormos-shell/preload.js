const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('electronAPI', {
  getSystemStats: () => ipcRenderer.invoke('get-system-stats'),
  getTime: () => ipcRenderer.invoke('get-time'),
  execCommand: (cmd) => ipcRenderer.invoke('exec-command', cmd),
  launchApp: (appPath) => ipcRenderer.invoke('launch-app', appPath)
});
