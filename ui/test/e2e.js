// End-to-end UI test: the real renderer in Chromium, bridged through the real pipe
// client to the Watchtower dev host (real Core logic, simulated Windows data).
// Starts its own fresh dev host on a private pipe, so runs are repeatable.
//
//   dotnet build tools/Watchtower.DevHost && node ui/test/e2e.js [--standard-user]
//
// Screenshots go to ui/test-results/. Set CHROMIUM_PATH to use a preinstalled browser.
const { chromium } = require('playwright');
const assert = require('node:assert');
const { spawn } = require('child_process');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { ServiceClient } = require('../lib/serviceClient');

const standardUser = process.argv.includes('--standard-user');
const OUT = path.join(__dirname, '..', 'test-results', standardUser ? 'standard-user' : 'admin');
fs.mkdirSync(OUT, { recursive: true });

function startDevHost() {
  const pipeName = `Watchtower.e2e.${process.pid}`;
  const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'wt-e2e-'));
  const project = path.join(__dirname, '..', '..', 'tools', 'Watchtower.DevHost');
  const args = ['run', '--project', project, '--no-build', '--', '--fresh', '--data', dataDir, ...(standardUser ? ['--standard-user'] : [])];
  const child = spawn('dotnet', args, { env: { ...process.env, WATCHTOWER_PIPE_NAME: pipeName }, stdio: ['ignore', 'ignore', 'inherit'] });
  const pipePath = process.platform === 'win32' ? `\\\\.\\pipe\\${pipeName}` : path.join(os.tmpdir(), `CoreFxPipe_${pipeName}`);
  const stop = () => {
    child.kill();
    fs.rmSync(dataDir, { recursive: true, force: true });
  };
  return { pipePath, stop };
}

async function main() {
  const host = startDevHost();
  process.on('exit', host.stop);
  const client = new ServiceClient({ pipePath: host.pipePath });
  const connected = new Promise((resolve, reject) => {
    client.once('connected', resolve);
    setTimeout(() => reject(new Error('Dev host did not start. Build it first: dotnet build tools/Watchtower.DevHost')), 30000);
  });
  client.start();
  await connected;

  const browser = await chromium.launch(process.env.CHROMIUM_PATH ? { executablePath: process.env.CHROMIUM_PATH } : {});
  const page = await browser.newPage({ viewport: { width: 1280, height: 840 } });
  const errors = [];
  page.on('console', (m) => m.type() === 'error' && errors.push(m.text()));
  page.on('pageerror', (e) => errors.push(String(e)));

  await page.exposeFunction('__rpc', async (method, params) => {
    try {
      return { ok: true, result: await client.request(method, params) };
    } catch (err) {
      return { ok: false, code: err.code, error: err.message };
    }
  });
  await page.addInitScript(() => {
    const listeners = { alert: [], snapshot: [], status: [] };
    window.__emit = (ch, data) => listeners[ch].forEach((cb) => cb(data));
    window.watchAPI = {
      rpc: (m, p) => window.__rpc(m, p),
      serviceStatus: async () => ({ connected: true }),
      onAlert: (cb) => listeners.alert.push(cb),
      onSnapshot: (cb) => listeners.snapshot.push(cb),
      onServiceStatus: (cb) => listeners.status.push(cb),
      exportHistory: async () => ({ ok: true, count: 1 }),
      chooseOffsiteFolder: async () => {
        const r = await window.__rpc('offsite.setDestination', { path: 'C:\\Users\\alex\\OneDrive\\Watchtower' });
        return r.ok ? { ok: true, result: r.result } : r;
      },
      openExternal: async () => {},
      openStoreSearch: async () => {},
      userApps: async (op) => (op === 'catalog' ? [{ id: 'news', label: 'News' }] : op === 'states' ? { news: 'installed' } : { ok: true }),
    };
  });
  client.on('event', (name, data) => page.evaluate(([n, d]) => window.__emit(n === 'alert' ? 'alert' : 'snapshot', d), [name, data]).catch(() => {}));

  let n = 0;
  const shot = (name) => page.screenshot({ path: path.join(OUT, `${String(++n).padStart(2, '0')}-${name}.png`) });
  const settle = () => page.waitForTimeout(300);

  await page.goto('file://' + path.join(__dirname, '..', 'renderer', 'index.html'));

  if (standardUser) {
    await page.waitForSelector('#modal:not(.hidden)');
    assert.match(await page.textContent('#modalBody'), /administrator/);
    await shot('setup-needs-admin');
    await page.click('#modalActions button');
    await page.waitForSelector('#feed .alert');
    assert.match(await page.textContent('#banner'), /standard account/);
    await page.click('.tab[data-tab="processes"]');
    await page.waitForSelector('#processTableBody tr');
    assert.ok(await page.locator('#processTableBody button:disabled').count() > 0, 'actions disabled for standard users');
    await settle();
    await shot('processes-read-only');
    // Even if the UI let it through, the service refuses: prove it at the protocol level.
    await assert.rejects(client.request('process.kill', { pid: 7788 }), (e) => e.code === 'forbidden');
  } else {
    await page.waitForSelector('#wizard:not(.hidden)');
    await shot('wizard-welcome');
    await page.click('#wizardNext');
    await page.click('text=support, administrator');
    await shot('wizard-accounts');
    await page.click('#wizardNext');
    await page.click('text=Quick Assist');
    await shot('wizard-remote-tools');
    await page.click('#wizardNext');
    await page.click('#wizardNext');
    await shot('wizard-updates');
    await page.click('#wizardNext');
    await page.click('text=Choose a folder');
    await page.waitForSelector('text=Change folder');
    await page.click('#wizardNext');
    await shot('wizard-done');
    await page.click('#wizardNext');
    await page.waitForSelector('#wizard.hidden', { state: 'attached' });

    await page.waitForSelector('#feed .alert');
    await settle();
    assert.equal(await page.locator('#feed .alert', { hasText: 'Action taken' }).count(), 0, 'audit entries stay out of the feed');
    await shot('alerts-feed');

    const masq = page.locator('#feed .alert', { hasText: 'pretending to be part of Windows' });
    await masq.locator('text=What does this mean?').click();
    assert.match(await masq.textContent(), /What to do/);
    await shot('alert-explained');

    const tool = page.locator('#feed .alert', { hasText: 'Remote-control program started' });
    await tool.locator('text=Trust…').click();
    await shot('trust-menu');
    await tool.locator('.menu button').first().click();
    await page.click('#modalActions >> text=Trust');
    // The trusted alert leaves the feed.
    await page.locator('#feed .alert', { hasText: 'Remote-control program started' }).waitFor({ state: 'detached' });

    await masq.locator('text=End program').click();
    await page.waitForSelector('#modal:not(.hidden)');
    assert.match(await page.textContent('#modalBody'), /isn't the real one/);
    await shot('guard-confirm');
    await page.click('#modalActions >> text=End program');
    await page.waitForSelector('#toast:has-text("was ended")');

    // The guard refuses to block the router, and says why.
    const decision = await client.request('guard.block', { address: '192.168.1.1' });
    assert.equal(decision.verdict, 'Deny');

    await page.click('.tab[data-tab="processes"]');
    await page.waitForSelector('#processTableBody tr');
    assert.equal(await page.locator('#processTableBody .tag.protected').count(), 2, 'System and lsass are protected');
    await settle();
    await shot('processes');

    await page.click('.tab[data-tab="exposure"]');
    await page.waitForSelector('#exposureBody .alert');
    await settle();
    await shot('exposure');

    await page.click('.tab[data-tab="health"]');
    await page.click('#runHealthBtn');
    await page.waitForSelector('text=Startup items worth a look');
    await settle();
    await shot('health');

    await page.click('.tab[data-tab="history"]');
    await page.waitForSelector('#historyList .alert');
    await page.click('#verifyBtn');
    await page.waitForSelector('#integrityBar.ok');
    await settle();
    await shot('history-verified');

    await page.click('.tab[data-tab="settings"]');
    await page.waitForSelector('#settingsBody .section-title');
    assert.match(await page.textContent('#settingsBody'), /AnyDesk\.exe/);
    await settle();
    await shot('settings');
  }

  assert.deepEqual(errors, [], 'no console errors');
  console.log(`UI E2E passed (${standardUser ? 'standard user' : 'administrator'}), ${n} screenshots in ${OUT}`);
  await browser.close();
  client.stop();
}

main().then(
  () => process.exit(0),
  (err) => {
    console.error('UI E2E FAILED:', err);
    process.exit(1);
  }
);
