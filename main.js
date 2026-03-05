const { app, BrowserWindow, ipcMain, shell } = require('electron');
const path = require('path');

let mainWindow;

function createWindow() {
  mainWindow = new BrowserWindow({
    width: 520,
    height: 780,
    minWidth: 480,
    minHeight: 680,
    title: 'Password Police',
    icon: path.join(__dirname, 'assets', 'icon.png'),
    backgroundColor: '#0a0b0f',
    webPreferences: {
      nodeIntegration: false,
      contextIsolation: true,
      preload: path.join(__dirname, 'preload.js'),
    },
    // Frameless-style with custom titlebar feel
    titleBarStyle: process.platform === 'darwin' ? 'hiddenInset' : 'default',
    autoHideMenuBar: true,
  });

  mainWindow.loadFile(path.join(__dirname, 'src', 'index.html'));

  mainWindow.on('closed', () => {
    mainWindow = null;
  });
}

app.whenReady().then(() => {
  createWindow();

  app.on('activate', () => {
    if (BrowserWindow.getAllWindows().length === 0) createWindow();
  });
});

app.on('window-all-closed', () => {
  if (process.platform !== 'darwin') app.quit();
});

// ── IPC: localStorage bridge (renderer <-> main via contextBridge) ──────────
// Electron's contextIsolation means we use a preload + ipcMain for storage.
ipcMain.handle('store-get', (_e, key) => {
  const Store = getStore();
  return Store.get(key, null);
});

ipcMain.handle('store-set', (_e, key, value) => {
  const Store = getStore();
  Store.set(key, value);
});

ipcMain.handle('store-delete', (_e, key) => {
  const Store = getStore();
  Store.delete(key);
});

ipcMain.handle('open-external', (_e, url) => {
  shell.openExternal(url);
});

// Lazy-load electron-store so it doesn't crash if not installed
let _store = null;
function getStore() {
  if (!_store) {
    try {
      const { default: Store } = require('electron-store');
      _store = new Store();
    } catch {
      // Fallback in-memory store if electron-store not installed
      const mem = {};
      _store = {
        get: (k, def) => (k in mem ? mem[k] : def),
        set: (k, v) => { mem[k] = v; },
        delete: (k) => { delete mem[k]; },
      };
    }
  }
  return _store;
}
