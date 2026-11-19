const logDiv = document.getElementById('log');
function appendLine(line) { logDiv.innerText += '\n' + line; logDiv.scrollTop = logDiv.scrollHeight; }

window.electronAPI.onNativeLog((msg) => appendLine('[INFO] ' + msg));
window.electronAPI.onNativeErr((msg) => appendLine('[ERR] ' + msg));
window.electronAPI.onNativeExit((code) => appendLine('[EXIT] ' + code));

appendLine('Electron wrapper ready.');
