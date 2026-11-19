const { app, BrowserWindow, Tray, Menu, ipcMain } = require('electron');
const { spawn } = require('child_process');
const path = require('path');

let mainWindow = null;
let tray = null;
let proc = null; // native process
app.isQuitting = false;

function createWindow() {
  mainWindow = new BrowserWindow({
    width: 1200,
    height: 800,
    webPreferences: {
      preload: path.join(__dirname, 'preload.js')
    }
  });

  mainWindow.loadFile(path.join(__dirname, 'renderer', 'index.html'));
  mainWindow.on('closed', () => { mainWindow = null; });
  mainWindow.on('close', (event) => {
    if (!app.isQuitting) {
      event.preventDefault();
      mainWindow.hide();
    }
  });
}

function createTray() {
  tray = new Tray(path.join(__dirname, 'icons', 'icon.png'));
  const contextMenu = Menu.buildFromTemplate([
    { label: 'Show', click: () => { if (mainWindow) mainWindow.show(); else createWindow(); } },
    { label: 'Exit', click: () => { app.quit(); } }
  ]);
  tray.setToolTip('BitCrack Distributed');
  tray.setContextMenu(contextMenu);
  tray.on('double-click', () => { if (mainWindow) mainWindow.show(); else createWindow(); });
}

function startNative() {
  // If packaged, the native Windows binary will be in resources.
  const isPackaged = app.isPackaged;
  const binaryPath = isPackaged
    ? path.join(process.resourcesPath, 'bitcrack-distributed-gui.exe')
    : path.join(__dirname, '..', '..', 'build_vs2022', 'bitcrack-distributed.exe');
  proc = spawn(binaryPath, ['--gui', '--mock']);
  proc.stdout.on('data', (data) => {
    const message = data.toString();
    if (mainWindow) mainWindow.webContents.send('native-log', message);
  });
  proc.stderr.on('data', (data) => {
    const message = data.toString();
    if (mainWindow) mainWindow.webContents.send('native-err', message);
  });
  proc.on('close', (code) => {
    if (mainWindow) mainWindow.webContents.send('native-exit', code);
  });
}

if (process.platform === 'win32') {
  app.setAppUserModelId('com.bitcrack.distributed');
}

app.whenReady().then(() => {
  createWindow();
  createTray();
  startNative();

  app.on('activate', function () {
    if (BrowserWindow.getAllWindows().length === 0) createWindow();
  });
});

app.on('window-all-closed', () => {
  // keep the app running in the tray
  if (process.platform !== 'darwin') {
    // app.quit();
  }
});

app.on('before-quit', () => {
  app.isQuitting = true;
  if (proc) proc.kill();
});

ipcMain.on('stop-native', () => {
  if (proc) { proc.kill(); proc = null; }
});

ipcMain.on('start-native', () => {
  if (!proc) startNative();
});
