const { runPowerShell } = require('./lib/exec');
const { loadSet, saveSet } = require('./lib/store');

const STORE_NAME = 'network-known';
let known = loadSet(STORE_NAME);
let baselineDone = known.size > 0; // an empty store means we've never run before

function toArray(parsed) {
  if (parsed == null) return [];
  return Array.isArray(parsed) ? parsed : [parsed];
}

async function getConnections() {
  const out = await runPowerShell(
    "Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue | " +
      'Select-Object LocalPort,RemoteAddress,RemotePort,OwningProcess | ConvertTo-Json -Compress'
  );
  return toArray(JSON.parse(out || 'null'));
}

async function getProcessNames() {
  const out = await runPowerShell(
    'Get-Process | Select-Object Id,ProcessName | ConvertTo-Json -Compress'
  );
  const rows = toArray(JSON.parse(out || 'null'));
  const map = new Map();
  rows.forEach((r) => map.set(r.Id, r.ProcessName));
  return map;
}

function isLoopback(addr) {
  return addr === '127.0.0.1' || addr === '::1' || addr?.startsWith('169.254.');
}

async function check() {
  const [connections, processNames] = await Promise.all([
    getConnections(),
    getProcessNames(),
  ]);

  const alerts = [];
  const snapshot = [];
  const currentKeys = new Set();

  for (const conn of connections) {
    if (!conn.RemoteAddress || isLoopback(conn.RemoteAddress)) continue;
    const procName = processNames.get(conn.OwningProcess) || `pid:${conn.OwningProcess}`;
    const key = `${procName}|${conn.RemoteAddress}`;
    currentKeys.add(key);
    snapshot.push({
      process: procName,
      pid: conn.OwningProcess,
      remoteAddress: conn.RemoteAddress,
      remotePort: conn.RemotePort,
      isNew: !known.has(key),
    });

    if (!known.has(key)) {
      if (baselineDone) {
        alerts.push({
          source: 'network',
          severity: 'info',
          title: 'New outbound connection',
          detail: `${procName} connected to ${conn.RemoteAddress}:${conn.RemotePort} for the first time.`,
          time: new Date().toISOString(),
        });
      }
      known.add(key);
    }
  }

  if (!baselineDone) {
    baselineDone = true;
  }
  saveSet(STORE_NAME, known);

  lastActivePids = new Set(snapshot.map((s) => s.pid));
  lastSnapshot = snapshot;

  return { alerts, snapshot };
}

// Lets other monitors (e.g. the process table, new-program watch) reuse
// this tick's connection data without re-running the same PowerShell query.
let lastActivePids = new Set();
let lastSnapshot = [];
function getActivePids() {
  return lastActivePids;
}
function getLastSnapshot() {
  return lastSnapshot;
}

module.exports = { check, getActivePids, getLastSnapshot };
