// Runs the real Electron app (main process, preload bridge, pipe client) against a fresh dev
// host and completes the setup guide, including choosing a backup folder. Only the native
// folder dialog is stubbed. Needs a display: on Linux run it under `xvfb-run -a`.
const { _electron: electron } = require('playwright');
const assert = require('node:assert');
const { spawn } = require('child_process');
const fs = require('fs');
const os = require('os');
const path = require('path');

const root = path.join(__dirname, '..');
const pipeName = `Watchtower.electron.${process.pid}`;
const pipePath = process.platform === 'win32' ? `\\\\.\\pipe\\${pipeName}` : path.join(os.tmpdir(), `CoreFxPipe_${pipeName}`);
const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'wt-electron-'));
const backupDir = fs.mkdtempSync(path.join(os.tmpdir(), 'wt-backup-'));

const host = spawn('dotnet', ['run', '--project', path.join(root, '..', 'tools', 'Watchtower.DevHost'), '--no-build', '--', '--fresh', '--data', dataDir],
  { env: { ...process.env, WATCHTOWER_PIPE_NAME: pipeName }, stdio: ['ignore', 'ignore', 'inherit'] });

async function waitForPipe() {
  for (let i = 0; i < 60; i++) {
    if (process.platform === 'win32' || fs.existsSync(pipePath)) return;
    await new Promise((r) => setTimeout(r, 500));
  }
  throw new Error('dev host did not start');
}

async function main() {
  await waitForPipe();
  const app = await electron.launch({
    executablePath: require('electron'),
    args: [...(process.platform === 'linux' ? ['--no-sandbox'] : []), root],
    env: { ...process.env, WATCHTOWER_PIPE: pipePath },
  });
  const errors = [];
  const win = await app.firstWindow();
  win.on('pageerror', (e) => errors.push(String(e)));
  win.on('console', (m) => m.type() === 'error' && errors.push(m.text()));

  // The native folder picker can't be driven by automation; answer it with a real folder.
  await app.evaluate(({ dialog }, dir) => {
    dialog.showOpenDialog = async () => ({ canceled: false, filePaths: [dir] });
  }, backupDir);

  await win.waitForSelector('#wizard:not(.hidden)', { timeout: 30_000 });
  for (let i = 0; i < 5; i++) await win.click('#wizardNext');
  assert.match(await win.textContent('#wizardTitle'), /Keep a copy/);
  await win.click('text=Choose a folder');
  await win.waitForSelector(`text=Change folder`, { timeout: 10_000 });
  assert.ok((await win.textContent('#wizardBody')).includes(backupDir), 'chosen folder shown');
  await win.click('#wizardNext');
  assert.match(await win.textContent('#wizardTitle'), /All set/);
  await win.click('#wizardNext');
  await win.waitForSelector('#wizard.hidden', { state: 'attached', timeout: 15_000 });
  assert.equal((await win.textContent('#wizardError')).trim(), '', 'no setup error');

  await win.click('.tab[data-tab="settings"]');
  await win.waitForSelector('#settingsBody .section-title');
  assert.ok((await win.textContent('#settingsBody')).includes(backupDir), 'backup folder saved');

  // Reopen and close the guide with its close button.
  await win.click('text=Run the setup guide again');
  await win.waitForSelector('#wizard:not(.hidden)');
  await win.click('#wizardClose');
  await win.waitForSelector('#wizard.hidden', { state: 'attached' });

  assert.deepEqual(errors, [], 'no renderer errors');
  await app.close();
  console.log('Electron smoke test passed: setup guide and backup folder work through the real app.');
}

main()
  .then(() => 0, (err) => {
    console.error('ELECTRON SMOKE FAILED:', err);
    return 1;
  })
  .then((code) => {
    host.kill();
    fs.rmSync(dataDir, { recursive: true, force: true });
    fs.rmSync(backupDir, { recursive: true, force: true });
    process.exit(code);
  });
