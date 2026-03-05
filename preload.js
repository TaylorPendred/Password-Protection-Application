const { contextBridge, ipcRenderer, shell } = require('electron');

// Expose a safe storage API to the renderer (replaces localStorage)
contextBridge.exposeInMainWorld('electronStore', {
  get:    (key)        => ipcRenderer.invoke('store-get', key),
  set:    (key, value) => ipcRenderer.invoke('store-set', key, value),
  delete: (key)        => ipcRenderer.invoke('store-delete', key),
});

// Expose shell for opening external URLs safely
contextBridge.exposeInMainWorld('openExternal', (url) => {
  ipcRenderer.invoke('open-external', url);
});
