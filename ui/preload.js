const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('watchAPI', {
  rpc: (method, params) => ipcRenderer.invoke('rpc', method, params),
  serviceStatus: () => ipcRenderer.invoke('service-status'),
  onAlert: (cb) => ipcRenderer.on('alert', (_e, data) => cb(data)),
  onSnapshot: (cb) => ipcRenderer.on('snapshot', (_e, data) => cb(data)),
  onServiceStatus: (cb) => ipcRenderer.on('service-status', (_e, data) => cb(data)),

  exportHistory: (format, source) => ipcRenderer.invoke('export-history', { format, source }),
  chooseOffsiteFolder: () => ipcRenderer.invoke('choose-offsite-folder'),
  openExternal: (target) => ipcRenderer.invoke('open-external', target),
  openStoreSearch: (term) => ipcRenderer.invoke('open-store-search', term),
  userApps: (op, id, install) => ipcRenderer.invoke('user-apps', { op, id, install }),
});
