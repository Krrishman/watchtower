const path = require('path');

// In a packaged build, __dirname resolves inside app.asar, which is READ-ONLY —
// every write would silently fail. Electron's userData path is the correct
// writable location (%APPDATA%\Watchtower on Windows). Falling back to a local
// ./store keeps `npm start` working when Electron isn't available (e.g. tests).
function resolveDataDir() {
  try {
    const electron = require('electron');
    const app = electron.app || (electron.remote && electron.remote.app);
    if (app && typeof app.getPath === 'function') {
      return path.join(app.getPath('userData'), 'store');
    }
  } catch {
    // Not running under Electron — fall through.
  }
  return path.join(__dirname, '..', '..', 'store');
}

const DATA_DIR = resolveDataDir();

module.exports = { DATA_DIR };
