const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('watchAPI', {
  onAlert: (cb) => ipcRenderer.on('alert', (_e, data) => cb(data)),
  onStatus: (cb) => ipcRenderer.on('status', (_e, data) => cb(data)),
  onMonitorError: (cb) => ipcRenderer.on('monitor-error', (_e, data) => cb(data)),
  onSnapshot: (key, cb) => ipcRenderer.on(`snapshot:${key}`, (_e, data) => cb(data)),
  onElevation: (cb) => ipcRenderer.on('elevation', (_e, data) => cb(data)),
  getElevation: () => ipcRenderer.invoke('get-elevation'),
  start: () => ipcRenderer.send('start-monitoring'),
  stop: () => ipcRenderer.send('stop-monitoring'),

  getHistory: (opts) => ipcRenderer.invoke('get-history', opts),

  getKnownUsers: () => ipcRenderer.invoke('get-known-users'),
  addKnownUser: (name) => ipcRenderer.invoke('add-known-user', name),
  removeKnownUser: (name) => ipcRenderer.invoke('remove-known-user', name),

  getDefenderStatus: () => ipcRenderer.invoke('get-defender-status'),
  runHealthCheck: () => ipcRenderer.invoke('run-health-check'),
  openWindowsSecurity: () => ipcRenderer.invoke('open-windows-security'),
  openStoreSearch: (term) => ipcRenderer.invoke('open-store-search', term),

  killProcess: (pid) => ipcRenderer.invoke('kill-process', pid),
  disconnectSession: (sessionId) => ipcRenderer.invoke('disconnect-session', sessionId),
  blockAddress: (address) => ipcRenderer.invoke('block-address', address),
  unblockAddress: (address) => ipcRenderer.invoke('unblock-address', address),
  listBlockedAddresses: () => ipcRenderer.invoke('list-blocked-addresses'),
  removeAutostartEntry: (entry) => ipcRenderer.invoke('remove-autostart-entry', entry),

  getDebloatCatalog: () => ipcRenderer.invoke('get-debloat-catalog'),
  getDebloatFeatureStates: () => ipcRenderer.invoke('get-debloat-feature-states'),
  getDebloatAppStates: () => ipcRenderer.invoke('get-debloat-app-states'),
  setDebloatFeature: (id, enable) => ipcRenderer.invoke('set-debloat-feature', { id, enable }),
  setDebloatApp: (id, install) => ipcRenderer.invoke('set-debloat-app', { id, install }),

  getAutostart: () => ipcRenderer.invoke('get-autostart'),
  setAutostart: (enable) => ipcRenderer.invoke('set-autostart', enable),

  getWatchlist: () => ipcRenderer.invoke('get-watchlist'),
  addWatchlistEntry: (name) => ipcRenderer.invoke('add-watchlist-entry', name),
  removeWatchlistEntry: (name) => ipcRenderer.invoke('remove-watchlist-entry', name),
  restoreWatchlistEntry: (name) => ipcRenderer.invoke('restore-watchlist-entry', name),

  exportHistory: (opts) => ipcRenderer.invoke('export-history', opts),
  verifyHistory: () => ipcRenderer.invoke('verify-history'),

  scanExposure: () => ipcRenderer.invoke('scan-exposure'),
  openRdpSettings: () => ipcRenderer.invoke('open-rdp-settings'),
  openFirewallSettings: () => ipcRenderer.invoke('open-firewall-settings'),
  openProxySettings: () => ipcRenderer.invoke('open-proxy-settings'),

  getOffsiteSettings: () => ipcRenderer.invoke('get-offsite-settings'),
  setOffsiteEnabled: (enabled) => ipcRenderer.invoke('set-offsite-enabled', enabled),
  setOffsiteInterval: (minutes) => ipcRenderer.invoke('set-offsite-interval', minutes),
  chooseOffsiteFolder: () => ipcRenderer.invoke('choose-offsite-folder'),
  syncOffsiteNow: () => ipcRenderer.invoke('sync-offsite-now'),
  onProcessEvents: (cb) => ipcRenderer.on('process-events', (_e, d) => cb(d)),
});
