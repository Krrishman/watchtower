// Checks an installed Watchtower service end to end over its pipe (used by CI after installing
// the MSI): read calls, then the same "change something" calls the setup guide and Settings make.
const fs = require('fs');
const os = require('os');
const path = require('path');
const { ServiceClient } = require('../lib/serviceClient');

async function connect() {
  const client = new ServiceClient();
  await new Promise((resolve, reject) => {
    client.once('connected', resolve);
    setTimeout(() => reject(new Error('could not connect to the service pipe')), 10_000);
    client.start();
  });
  return client;
}

async function step(client, label, method, params, check) {
  const started = Date.now();
  try {
    const result = await client.request(method, params);
    if (check) check(result);
    console.log(`ok   ${label} (${Date.now() - started} ms)`);
    return result;
  } catch (err) {
    console.error(`FAIL ${label} (${Date.now() - started} ms): [${err.code || 'error'}] ${err.message}`);
    throw err;
  }
}

async function run() {
  const client = await connect();
  try {
    const hello = await step(client, 'hello', 'hello', {}, (h) => {
      if (h.protocol !== 1) throw new Error('unexpected protocol version');
    });
    console.log(`     caller: ${hello.user}, admin: ${hello.isAdmin}`);
    await step(client, 'verify history', 'history.verify', {}, (v) => {
      if (!v.ok) throw new Error(v.message);
    });
    const state = await step(client, 'state', 'state.get', {});
    console.log(`     sensors: ${JSON.stringify(state.sensors)}`);

    const backup = path.join(os.tmpdir(), 'wt-ci-backup');
    fs.mkdirSync(backup, { recursive: true });
    await step(client, 'choose backup folder', 'offsite.setDestination', { path: backup });
    await step(client, 'finish setup', 'setup.complete', { trustedAccounts: [], usedTools: ['quickassist.exe'], learning: true, autoUpdate: true, updateRing: 'standard', crashReports: false });
    await step(client, 'enable backup', 'offsite.setEnabled', { enabled: true });
    await step(client, 'back up now', 'offsite.syncNow', {}, (r) => {
      if (!r.ok) throw new Error(r.error);
    });
    await step(client, 'settings saved', 'settings.get', {}, (s) => {
      if (!s.setupCompleted || !s.offsite.enabled) throw new Error(`settings not saved: ${JSON.stringify(s)}`);
    });
    const rule = await step(client, 'trust something', 'trust.add', { type: 'address', value: '203.0.113.9', label: '203.0.113.9' });
    await step(client, 'remove trust', 'trust.remove', { id: rule.id });
    const recent = await step(client, 'recent alerts', 'alerts.recent', { limit: 20 });
    if (recent.length) await step(client, 'dismiss alert', 'alerts.dismiss', { ids: [recent[0].id] });
    await step(client, 'history after changes', 'history.verify', {}, (v) => {
      if (!v.ok) throw new Error(v.message);
    });
  } finally {
    client.stop();
  }
}

(async () => {
  for (let i = 1; i <= 3; i++) {
    try {
      await run();
      console.log('Installed service passed every check.');
      process.exit(0);
    } catch (err) {
      console.error(`attempt ${i} failed: ${err.message}`);
      await new Promise((r) => setTimeout(r, 3000));
    }
  }
  process.exit(1);
})();
