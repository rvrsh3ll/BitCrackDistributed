const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('electronAPI', {
  onNativeLog: (cb) => ipcRenderer.on('native-log', (ev, msg) => cb(msg)),
  onNativeErr: (cb) => ipcRenderer.on('native-err', (ev, msg) => cb(msg)),
  onNativeExit: (cb) => ipcRenderer.on('native-exit', (ev, code) => cb(code)),
  stopNative: () => ipcRenderer.send('stop-native'),
  startNative: () => ipcRenderer.send('start-native')
});
