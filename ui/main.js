const { app, BrowserWindow, ipcMain, Notification, shell, Tray, Menu, dialog } = require('electron');
const path = require('path');
const { exec } = require('child_process');

const sessions = require('./monitors/sessions');
const processes = require('./monitors/processes');
const network = require('./monitors/network');
const cameraMic = require('./monitors/cameraMic');
const eventlog = require('./monitors/eventlog');
const processTable = require('./monitors/processTable');
const newProgramWatch = require('./monitors/newProgramWatch');
const healthCheck = require('./monitors/healthCheck');
const remediate = require('./monitors/remediate');
const debloat = require('./monitors/debloat');
const autostartApp = require('./monitors/autostartApp');
const processEvents = require('./monitors/processEvents');
const offsite = require('./monitors/offsite');
const networkExposure = require('./monitors/networkExposure');
const history = require('./monitors/lib/history');
const { loadJson, saveJson } = require('./monitors/lib/store');

let mainWindow = null;
let tray = null;
let isQuitting = false;
let timers = [];
let monitoring = false;

// Whether this process has administrator rights. Several monitors and most
// debloat toggles need it, so the UI states this up front instead of letting
// the user discover it through a string of failures.
let isElevated = null;

function checkElevation() {
  return new Promise((resolve) => {
    exec(
      'powershell -NoProfile -NonInteractive -Command "(New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)"',
      { timeout: 10_000, windowsHide: true },
      (err, stdout) => {
        if (err) {
          resolve(false);
          return;
        }
        resolve(stdout.trim().toLowerCase() === 'true');
      }
    );
  });
}

const POLL_INTERVALS = {
  sessions: 15_000,
  processes: 10_000,
  network: 20_000,
  cameraMic: 20_000,
  eventlog: 30_000,
  processTable: 25_000,
  newProgramWatch: 15_000,
};

function createWindow() {
  mainWindow = new BrowserWindow({
    width: 1280,
    height: 820,
    minWidth: 960,
    minHeight: 640,
    backgroundColor: '#10151c',
    webPreferences: {
      preload: path.join(__dirname, 'preload.js'),
      contextIsolation: true,
      nodeIntegration: false,
    },
  });
  mainWindow.setMenuBarVisibility(false);
  mainWindow.loadFile(path.join(__dirname, 'renderer', 'index.html'));

  // Closing the window hides it instead of quitting, so monitoring and the
  // history log keep running in the background — the whole point of a watcher.
  mainWindow.on('close', (e) => {
    if (!isQuitting) {
      e.preventDefault();
      mainWindow.hide();
    }
  });
}

function createTray() {
  try {
    const { nativeImage } = require('electron');
    // A real icon matters here: since closing the window only hides it, an
    // invisible tray icon would leave no way to restore or quit the app.
    const iconPath = path.join(__dirname, 'renderer', 'tray-icon.png');
    let icon = nativeImage.createFromPath(iconPath);
    if (icon.isEmpty()) icon = nativeImage.createEmpty();
    tray = new Tray(icon);
    tray.setToolTip('Watchtower — monitoring');
    tray.setContextMenu(
      Menu.buildFromTemplate([
        { label: 'Open Watchtower', click: () => { if (mainWindow) mainWindow.show(); } },
        { type: 'separator' },
        {
          label: 'Quit (stops monitoring)',
          click: () => {
            isQuitting = true;
            app.quit();
          },
        },
      ])
    );
    tray.on('double-click', () => { if (mainWindow) mainWindow.show(); });
  } catch (e) {
    // Tray creation failed — fall back to quitting on window close so the app
    // can't become unreachable with no window and no tray icon.
    isQuitting = true;
  }
}

function send(channel, payload) {
  if (mainWindow && !mainWindow.isDestroyed()) {
    mainWindow.webContents.send(channel, payload);
  }
}

function emitAlert(alert) {
  // alert: { source, severity: 'info'|'warn'|'critical', title, detail, time, meta? }
  send('alert', alert);
  history.append(alert);
  if (alert.severity === 'critical') offsite.onCriticalAlert();
  if (alert.severity !== 'info') {
    try {
      new Notification({ title: alert.title, body: alert.detail }).show();
    } catch (e) {
      // Notifications can fail on some Windows configs (missing AppUserModelID
      // when unpackaged); the in-app feed and history still capture it either way.
    }
  }
}

function startMonitoring() {
  if (monitoring) return;
  monitoring = true;

  const runners = [
    { mod: sessions, key: 'sessions' },
    { mod: processes, key: 'processes' },
    { mod: network, key: 'network' },
    { mod: cameraMic, key: 'cameraMic' },
    { mod: eventlog, key: 'eventlog' },
    { mod: processTable, key: 'processTable' },
    { mod: newProgramWatch, key: 'newProgramWatch' },
  ];

  runners.forEach(({ mod, key }) => {
    let running = false;
    const tick = async () => {
      if (!monitoring) return;
      // A slow check (PowerShell can stall for seconds) must not have a second
      // copy start on top of it — that compounds into a backlog of processes.
      if (running) return;
      running = true;
      try {
        const result = await mod.check();
        if (result && result.alerts) result.alerts.forEach(emitAlert);
        if (result && result.snapshot) send(`snapshot:${key}`, result.snapshot);
      } catch (err) {
        send('monitor-error', { key, message: err.message });
      } finally {
        running = false;
      }
    };
    tick();
    timers.push(setInterval(tick, POLL_INTERVALS[key]));
  });

  history.trimIfNeeded();
  offsite.start();
  startProcessEvents();
  send('status', { monitoring: true });
}

// Real-time process-start detection. This supplements the pollers rather than
// replacing them: the pollers still catch anything already running, while this
// catches short-lived processes that start and exit between polls.
function startProcessEvents() {
  processEvents.on('ready', () => {
    send('process-events', { active: true });
    emitAlert({
      source: 'processEvents',
      severity: 'info',
      title: 'Real-time process monitoring active',
      detail: 'Every process launch is now checked instantly, not just on the polling interval.',
      time: new Date().toISOString(),
    });
  });

  processEvents.on('unavailable', (reason) => {
    send('process-events', { active: false, reason });
  });

  processEvents.on('process-start', (proc) => {
    const lname = (proc.name || '').toLowerCase();
    const watchlist = processes.getWatchlistInfo();
    const active = new Set([
      ...watchlist.defaults.filter((d) => !d.disabled).map((d) => d.name),
      ...watchlist.custom,
    ]);
    if (active.has(lname)) {
      emitAlert({
        source: 'processEvents',
        severity: 'warn',
        title: 'Remote-access tool launched',
        detail: `${proc.name} started (PID ${proc.pid}), detected instantly on launch.`,
        time: new Date().toISOString(),
      });
    }
  });

  processEvents.start();
}

function stopMonitoring() {
  monitoring = false;
  timers.forEach(clearInterval);
  timers = [];
  processEvents.stop();
  processEvents.removeAllListeners();
  offsite.stop();
  send('process-events', { active: false });
  send('status', { monitoring: false });
}

ipcMain.on('start-monitoring', startMonitoring);
ipcMain.on('stop-monitoring', stopMonitoring);

ipcMain.handle('get-history', (_e, opts) => history.readAll(opts || {}));

ipcMain.handle('get-known-users', () => loadJson('known-users', []));
ipcMain.handle('add-known-user', (_e, name) => {
  const list = loadJson('known-users', []);
  const clean = String(name || '').trim();
  if (clean && !list.some((u) => u.toLowerCase() === clean.toLowerCase())) {
    list.push(clean);
    saveJson('known-users', list);
  }
  return list;
});
ipcMain.handle('remove-known-user', (_e, name) => {
  const list = loadJson('known-users', []).filter(
    (u) => u.toLowerCase() !== String(name || '').toLowerCase()
  );
  saveJson('known-users', list);
  return list;
});

ipcMain.handle('get-defender-status', () => healthCheck.getDefenderStatus());
ipcMain.handle('run-health-check', () => healthCheck.runFullCheck());
ipcMain.handle('open-windows-security', () => shell.openExternal('windowsdefender://threat'));
ipcMain.handle('open-store-search', (_e, term) =>
  shell.openExternal(`ms-windows-store://search/?query=${encodeURIComponent(term)}`)
);

ipcMain.handle('kill-process', (_e, pid) => remediate.killProcess(pid));
ipcMain.handle('disconnect-session', (_e, sessionId) => remediate.disconnectSession(sessionId));
ipcMain.handle('block-address', (_e, address) => remediate.blockAddress(address));
ipcMain.handle('unblock-address', (_e, address) => remediate.unblockAddress(address));
ipcMain.handle('list-blocked-addresses', () => remediate.listBlockedAddresses());
ipcMain.handle('remove-autostart-entry', (_e, entry) => remediate.removeAutostartEntry(entry));

ipcMain.handle('get-debloat-catalog', () => debloat.getCatalog());
ipcMain.handle('get-debloat-feature-states', () => debloat.getFeatureStates());
ipcMain.handle('get-debloat-app-states', () => debloat.getAppStates());
ipcMain.handle('set-debloat-feature', (_e, { id, enable }) => debloat.setFeature(id, enable));
ipcMain.handle('set-debloat-app', (_e, { id, install }) => debloat.setApp(id, install));

ipcMain.handle('get-elevation', () => isElevated);

ipcMain.handle('verify-history', () => history.verify());

ipcMain.handle('scan-exposure', () => networkExposure.scan());
ipcMain.handle('open-rdp-settings', () => shell.openExternal('ms-settings:remotedesktop'));
ipcMain.handle('open-firewall-settings', () => shell.openExternal('ms-settings:windowsdefender'));
ipcMain.handle('open-proxy-settings', () => shell.openExternal('ms-settings:network-proxy'));

ipcMain.handle('get-offsite-settings', () => offsite.getSettings());
ipcMain.handle('set-offsite-enabled', (_e, enabled) => offsite.setEnabled(enabled));
ipcMain.handle('set-offsite-interval', (_e, minutes) => offsite.setIntervalMinutes(minutes));
ipcMain.handle('sync-offsite-now', () => offsite.syncNow());
ipcMain.handle('choose-offsite-folder', async () => {
  const result = await dialog.showOpenDialog(mainWindow, {
    title: 'Choose a folder to mirror history into',
    properties: ['openDirectory', 'createDirectory'],
  });
  if (result.canceled || !result.filePaths.length) return { canceled: true };
  return { canceled: false, settings: offsite.setDestination(result.filePaths[0]) };
});

ipcMain.handle('get-autostart', () => autostartApp.isEnabled());
ipcMain.handle('set-autostart', (_e, enable) =>
  enable ? autostartApp.enable() : autostartApp.disable()
);

ipcMain.handle('get-watchlist', () => processes.getWatchlistInfo());
ipcMain.handle('add-watchlist-entry', (_e, name) => {
  const clean = String(name || '').trim().toLowerCase();
  if (!clean) return processes.getWatchlistInfo();
  const list = loadJson('custom-watchlist', []);
  if (!list.some((n) => String(n).toLowerCase() === clean)) {
    list.push(clean);
    saveJson('custom-watchlist', list);
  }
  return processes.getWatchlistInfo();
});
ipcMain.handle('remove-watchlist-entry', (_e, name) => {
  const clean = String(name || '').trim().toLowerCase();
  const custom = loadJson('custom-watchlist', []);
  const filtered = custom.filter((n) => String(n).toLowerCase() !== clean);
  if (filtered.length !== custom.length) {
    saveJson('custom-watchlist', filtered);
  } else {
    // It's a built-in entry — record it as disabled rather than editing defaults.
    const disabled = loadJson('watchlist-disabled', []);
    if (!disabled.some((n) => String(n).toLowerCase() === clean)) {
      disabled.push(clean);
      saveJson('watchlist-disabled', disabled);
    }
  }
  return processes.getWatchlistInfo();
});
ipcMain.handle('restore-watchlist-entry', (_e, name) => {
  const clean = String(name || '').trim().toLowerCase();
  const disabled = loadJson('watchlist-disabled', []).filter(
    (n) => String(n).toLowerCase() !== clean
  );
  saveJson('watchlist-disabled', disabled);
  return processes.getWatchlistInfo();
});

ipcMain.handle('export-history', async (_e, { format = 'csv', source = null } = {}) => {
  const stamp = new Date().toISOString().slice(0, 10);
  const result = await dialog.showSaveDialog(mainWindow, {
    title: 'Export Watchtower history',
    defaultPath: `watchtower-history-${stamp}.${format}`,
    filters:
      format === 'json'
        ? [{ name: 'JSON', extensions: ['json'] }]
        : [{ name: 'CSV', extensions: ['csv'] }],
  });
  if (result.canceled || !result.filePath) return { ok: false, canceled: true };
  try {
    const count = history.exportTo(result.filePath, format, { source });
    return { ok: true, count, filePath: result.filePath };
  } catch (err) {
    return { ok: false, error: err.message };
  }
});

app.whenReady().then(async () => {
  // Named app ID so Windows toast notifications actually appear when running
  // unpackaged — without it, Notification silently no-ops on many setups.
  if (process.platform === 'win32') app.setAppUserModelId('com.local.watchtower');

  createWindow();
  createTray();

  isElevated = await checkElevation();
  send('elevation', { isElevated });

  startMonitoring();

  app.on('activate', () => {
    if (BrowserWindow.getAllWindows().length === 0) createWindow();
  });
});

app.on('before-quit', () => {
  isQuitting = true;
  processEvents.stop(); // don't orphan the PowerShell child process
  offsite.stop();
});

app.on('window-all-closed', () => {
  // Deliberately does NOT quit: the tray keeps monitoring alive in the
  // background. Quit explicitly from the tray menu.
});
