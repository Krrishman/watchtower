const fs = require('fs');
const path = require('path');
const os = require('os');
const { loadJson, saveJson } = require('./lib/store');
const { DATA_DIR } = require('./lib/paths');

// A local-only log is worthless once the machine is fully compromised — the
// attacker just deletes it. Mirroring to a cloud-synced folder (OneDrive,
// Dropbox, Google Drive) or a network share means the record survives, and
// those services' own version history defeats an overwrite.

const SETTINGS_KEY = 'offsite-settings';
const FILES = ['history.jsonl', 'history-anchor.json', 'history-highwater.json'];

let syncTimer = null;
let pendingCritical = null;

function getSettings() {
  return loadJson(SETTINGS_KEY, { destination: null, enabled: false, intervalMinutes: 15, lastSync: null, lastError: null });
}

function saveSettings(next) {
  saveJson(SETTINGS_KEY, { ...getSettings(), ...next });
  return getSettings();
}

function machineTag() {
  // Namespacing by machine keeps multiple PCs syncing to one shared folder
  // from overwriting each other.
  return os.hostname().replace(/[^A-Za-z0-9_-]/g, '_') || 'unknown-host';
}

function syncNow() {
  const settings = getSettings();
  if (!settings.destination) {
    return { ok: false, error: 'No destination folder set.' };
  }

  try {
    const targetDir = path.join(settings.destination, `watchtower-${machineTag()}`);
    if (!fs.existsSync(targetDir)) fs.mkdirSync(targetDir, { recursive: true });

    let copied = 0;
    for (const name of FILES) {
      const src = path.join(DATA_DIR, name);
      if (!fs.existsSync(src)) continue;
      // Write to a temp name then rename, so a sync interrupted midway can't
      // leave a truncated log at the destination.
      const dest = path.join(targetDir, name);
      const tmp = `${dest}.tmp`;
      fs.copyFileSync(src, tmp);
      fs.renameSync(tmp, dest);
      copied += 1;
    }

    if (copied === 0) {
      return { ok: false, error: 'Nothing to sync yet — no history recorded.' };
    }

    fs.writeFileSync(
      path.join(targetDir, 'last-sync.txt'),
      `Machine: ${os.hostname()}\nLast sync: ${new Date().toISOString()}\nFiles: ${copied}\n`,
      'utf8'
    );

    saveSettings({ lastSync: new Date().toISOString(), lastError: null });
    return { ok: true, copied, targetDir };
  } catch (err) {
    const msg = /ENOENT|no such file/i.test(err.message)
      ? `Destination folder is unreachable (${err.message}). If it's a network share or a cloud folder, check it's still mounted.`
      : err.message;
    saveSettings({ lastError: msg });
    return { ok: false, error: msg };
  }
}

function start() {
  stop();
  const settings = getSettings();
  if (!settings.enabled || !settings.destination) return;
  const ms = Math.max(1, settings.intervalMinutes) * 60_000;
  syncNow();
  syncTimer = setInterval(syncNow, ms);
}

function stop() {
  if (syncTimer) clearInterval(syncTimer);
  syncTimer = null;
  if (pendingCritical) clearTimeout(pendingCritical);
  pendingCritical = null;
}

// Critical alerts shouldn't wait for the next interval — that's exactly the
// window an attacker would use. Debounced so a burst of alerts triggers one
// sync rather than a dozen.
function onCriticalAlert() {
  const settings = getSettings();
  if (!settings.enabled || !settings.destination) return;
  if (pendingCritical) return;
  pendingCritical = setTimeout(() => {
    pendingCritical = null;
    syncNow();
  }, 5000);
}

function setDestination(destination) {
  const next = saveSettings({ destination });
  if (next.enabled) start();
  return next;
}

function setEnabled(enabled) {
  const next = saveSettings({ enabled });
  if (enabled) start();
  else stop();
  return next;
}

function setInterval_(minutes) {
  const next = saveSettings({ intervalMinutes: Math.max(1, Number(minutes) || 15) });
  if (next.enabled) start();
  return next;
}

module.exports = {
  getSettings,
  setDestination,
  setEnabled,
  setIntervalMinutes: setInterval_,
  syncNow,
  start,
  stop,
  onCriticalAlert,
};
