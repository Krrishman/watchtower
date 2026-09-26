const { app, BrowserWindow, ipcMain, Notification, shell, Tray, Menu, dialog, crashReporter, nativeImage } = require('electron');
const fs = require('fs');
const path = require('path');
const { ServiceClient } = require('./lib/serviceClient');
const userApps = require('./lib/userApps');

// Crash dumps stay on this machine; nothing is uploaded from the UI.
crashReporter.start({ uploadToServer: false });
process.on('uncaughtException', (err) => {
  try {
    fs.appendFileSync(path.join(app.getPath('userData'), 'ui-errors.log'), `${new Date().toISOString()} ${err.stack || err}\n`);
  } catch {
    // Nowhere left to report it.
  }
});

if (!app.requestSingleInstanceLock()) {
  app.quit();
}

const startHidden = process.argv.includes('--hidden');
const SEVERITY_RANK = { info: 0, warn: 1, critical: 2 };
const EXTERNAL_TARGETS = {
  windowsSecurity: 'windowsdefender://threat',
  rdpSettings: 'ms-settings:remotedesktop',
  firewallSettings: 'ms-settings:windowsdefender',
  proxySettings: 'ms-settings:network-proxy',
  privacyCamera: 'ms-settings:privacy-webcam',
  privacyMicrophone: 'ms-settings:privacy-microphone',
};

let mainWindow = null;
let tray = null;
let quitting = false;
let notifyMinSeverity = 'warn';
let offlineTimer = null;
let offlineNotified = false;

const client = new ServiceClient();

function send(channel, payload) {
  if (mainWindow && !mainWindow.isDestroyed()) mainWindow.webContents.send(channel, payload);
}

function showWindow() {
  if (!mainWindow) createWindow();
  mainWindow.show();
  mainWindow.focus();
}

function createWindow() {
  mainWindow = new BrowserWindow({
    width: 1280,
    height: 840,
    minWidth: 980,
    minHeight: 640,
    show: !startHidden,
    backgroundColor: '#10151c',
    title: 'Watchtower',
    webPreferences: {
      preload: path.join(__dirname, 'preload.js'),
      contextIsolation: true,
      nodeIntegration: false,
      sandbox: true,
    },
  });
  mainWindow.setMenuBarVisibility(false);
  mainWindow.loadFile(path.join(__dirname, 'renderer', 'index.html'));

  // Nothing in the window should ever navigate away or open other windows.
  mainWindow.webContents.setWindowOpenHandler(() => ({ action: 'deny' }));
  mainWindow.webContents.on('will-navigate', (e) => e.preventDefault());

  mainWindow.on('close', (e) => {
    if (!quitting) {
      e.preventDefault();
      mainWindow.hide();
    }
  });
}

function createTray() {
  const icon = nativeImage.createFromPath(path.join(__dirname, 'renderer', 'tray-icon.png'));
  tray = new Tray(icon.isEmpty() ? nativeImage.createEmpty() : icon);
  updateTray();
  tray.on('double-click', showWindow);
}

function updateTray() {
  if (!tray) return;
  tray.setToolTip(client.connected ? 'Watchtower: monitoring' : 'Watchtower: service not running');
  tray.setContextMenu(
    Menu.buildFromTemplate([
      { label: 'Open Watchtower', click: showWindow },
      { label: client.connected ? 'Monitoring is on' : 'Monitoring service is not running', enabled: false },
      { type: 'separator' },
      {
        // Monitoring runs in the Windows service, so closing this window never stops it.
        label: 'Close this window (monitoring continues)',
        click: () => {
          quitting = true;
          app.quit();
        },
      },
    ])
  );
}

function notify(title, body) {
  if (!Notification.isSupported()) return;
  const n = new Notification({ title, body });
  n.on('click', showWindow);
  n.show();
}

async function refreshNotifyPreference() {
  try {
    const settings = await client.request('settings.get');
    notifyMinSeverity = settings.notifyMinSeverity || 'warn';
  } catch {
    // Keep the previous preference.
  }
}

client.on('connected', async () => {
  clearTimeout(offlineTimer);
  offlineNotified = false;
  updateTray();
  await refreshNotifyPreference();
  send('service-status', { connected: true });
});

client.on('disconnected', () => {
  updateTray();
  send('service-status', { connected: false });
  // A brief drop is normal while the service restarts or updates; a long one is worth telling someone about.
  clearTimeout(offlineTimer);
  offlineTimer = setTimeout(() => {
    if (!client.connected && !offlineNotified) {
      offlineNotified = true;
      notify('Watchtower is not monitoring', "The Watchtower service stopped and hasn't come back. Open Watchtower for details.");
    }
  }, 30_000);
});

client.on('event', (name, data) => {
  if (name === 'alert') {
    send('alert', data);
    if (!data.suppressedBy && data.source !== 'audit' && SEVERITY_RANK[data.severity] >= SEVERITY_RANK[notifyMinSeverity]) notify(data.title, data.detail);
  } else if (name === 'snapshot') {
    send('snapshot', data);
  }
});

// ---- renderer bridge ----

ipcMain.handle('rpc', async (_e, method, params) => {
  if (typeof method !== 'string' || !/^[a-z]+(\.[a-zA-Z]+)?$/.test(method)) throw new Error('Invalid method.');
  try {
    const result = await client.request(method, params);
    if (method === 'settings.update' || method === 'setup.complete') refreshNotifyPreference();
    return { ok: true, result };
  } catch (err) {
    return { ok: false, code: err.code || 'failed', error: err.message };
  }
});

ipcMain.handle('service-status', () => ({ connected: client.connected }));

ipcMain.handle('export-history', async (_e, { format, source }) => {
  const stamp = new Date().toISOString().slice(0, 10);
  const target = await dialog.showSaveDialog(mainWindow, {
    title: 'Export Watchtower history',
    defaultPath: `watchtower-history-${stamp}.${format === 'json' ? 'json' : 'csv'}`,
    filters: format === 'json' ? [{ name: 'JSON', extensions: ['json'] }] : [{ name: 'CSV', extensions: ['csv'] }],
  });
  if (target.canceled || !target.filePath) return { ok: false, canceled: true };
  try {
    const result = await client.request('history.export', { format, source });
    // Written by this process, as the signed-in user, never by the SYSTEM service.
    fs.writeFileSync(target.filePath, result.content, 'utf8');
    return { ok: true, count: result.count, filePath: target.filePath };
  } catch (err) {
    return { ok: false, error: err.message };
  }
});

ipcMain.handle('choose-offsite-folder', async () => {
  const result = await dialog.showOpenDialog(mainWindow, {
    title: 'Choose a folder to back up history into',
    properties: ['openDirectory', 'createDirectory'],
  });
  if (result.canceled || !result.filePaths.length) return { ok: false, canceled: true };
  try {
    return { ok: true, result: await client.request('offsite.setDestination', { path: result.filePaths[0] }) };
  } catch (err) {
    return { ok: false, error: err.message };
  }
});

ipcMain.handle('open-external', (_e, target) => {
  const url = EXTERNAL_TARGETS[target];
  if (url) shell.openExternal(url);
});

ipcMain.handle('open-store-search', (_e, term) =>
  shell.openExternal(`ms-windows-store://search/?query=${encodeURIComponent(String(term))}`)
);

ipcMain.handle('user-apps', async (_e, { op, id, install }) => {
  if (op === 'catalog') return userApps.catalog();
  if (op === 'states') return userApps.states();
  if (op === 'set') return userApps.set(id, install);
  return null;
});

app.on('second-instance', showWindow);

app.whenReady().then(() => {
  if (process.platform === 'win32') app.setAppUserModelId('com.watchtower.app');
  createWindow();
  createTray();
  client.start();
});

app.on('before-quit', () => {
  quitting = true;
  client.stop();
});

// The tray keeps the window process alive for notifications; quit only from the tray.
app.on('window-all-closed', () => {});
