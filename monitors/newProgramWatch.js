const { getProcessDetails } = require('./lib/processes');
const { runPowerShell } = require('./lib/exec');
const { loadSet, saveSet } = require('./lib/store');
const { snapshotAutostart } = require('./autostart');
const network = require('./network');

const STORE_NAME = 'known-programs';
const OBSERVE_WINDOW_MS = 5 * 60 * 1000; // watch a new program closely for 5 minutes

let known = loadSet(STORE_NAME);
let baselineDone = known.size > 0; // empty store means this is the very first run ever

// path -> { pid, observeUntil, preAutostart, alertedPorts: Set, alertedRemotes: Set, autostartAlerted: bool }
const observations = new Map();

function autostartKey(entry) {
  return `${entry.Location}|${entry.Name}|${entry.Command}`;
}

async function getListeningPorts() {
  const out = await runPowerShell(
    'Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue | ' +
      'Select-Object LocalPort,OwningProcess | ConvertTo-Json -Compress'
  );
  let parsed;
  try {
    parsed = JSON.parse(out || 'null');
  } catch {
    parsed = null;
  }
  const rows = parsed == null ? [] : Array.isArray(parsed) ? parsed : [parsed];
  return rows;
}

async function check() {
  const alerts = [];
  const procs = await getProcessDetails();

  // 1. Detect brand-new executables.
  // 1. Detect brand-new executables.
  // The autostart snapshot is expensive (enumerating scheduled tasks takes
  // seconds), so take it at most ONCE per tick and share it across every new
  // program found — an installer spawning several executables previously
  // triggered one slow snapshot each, stalling the whole monitor.
  let tickAutostart = null;
  let tickAutostartTaken = false;

  for (const proc of procs) {
    if (!proc.path) continue;
    const lpath = proc.path.toLowerCase();
    if (known.has(lpath)) continue;
    known.add(lpath);

    if (!baselineDone) continue; // first-ever run: learn silently, don't flood

    alerts.push({
      source: 'newProgramWatch',
      severity: 'info',
      title: 'New program seen for the first time',
      detail: `${proc.name} (${proc.path}) has never run on this machine before. Watching it closely for the next 5 minutes.`,
      time: new Date().toISOString(),
    });

    if (!tickAutostartTaken) {
      tickAutostartTaken = true;
      try {
        tickAutostart = await snapshotAutostart();
      } catch {
        tickAutostart = [];
      }
    }

    observations.set(lpath, {
      pid: proc.pid,
      observeUntil: Date.now() + OBSERVE_WINDOW_MS,
      preAutostart: tickAutostart || [],
      alertedPorts: new Set(),
      alertedRemotes: new Set(),
      autostartAlerted: false,
    });
  }

  if (!baselineDone) {
    baselineDone = true;
    saveSet(STORE_NAME, known);
    return { alerts: [] };
  }
  saveSet(STORE_NAME, known);

  // 2. Check active observations: listening ports, outbound connections, new persistence.
  if (observations.size) {
    const [listening, currentAutostart] = await Promise.all([
      getListeningPorts().catch(() => []),
      snapshotAutostart().catch(() => null),
    ]);
    const remoteSnapshot = network.getLastSnapshot();

    for (const [lpath, obs] of observations) {
      const proc = procs.find((p) => p.path && p.path.toLowerCase() === lpath);
      const pid = proc ? proc.pid : obs.pid;
      const name = proc ? proc.name : lpath;

      for (const l of listening) {
        if (l.OwningProcess === pid && !obs.alertedPorts.has(l.LocalPort)) {
          obs.alertedPorts.add(l.LocalPort);
          alerts.push({
            source: 'newProgramWatch',
            severity: 'critical',
            title: 'New program opened a listening port',
            detail: `${name} started listening on port ${l.LocalPort} shortly after its first run — this can let something outside your machine connect in.`,
            time: new Date().toISOString(),
          });
        }
      }

      for (const conn of remoteSnapshot) {
        if (conn.pid === pid) {
          const key = `${conn.remoteAddress}:${conn.remotePort}`;
          if (!obs.alertedRemotes.has(key)) {
            obs.alertedRemotes.add(key);
            alerts.push({
              source: 'newProgramWatch',
              severity: 'warn',
              title: 'New program connected out',
              detail: `${name} connected to ${conn.remoteAddress}:${conn.remotePort} shortly after its first run.`,
              time: new Date().toISOString(),
            });
          }
        }
      }

      if (!obs.autostartAlerted && currentAutostart) {
        const before = new Set(obs.preAutostart.map(autostartKey));
        const added = currentAutostart.filter((e) => !before.has(autostartKey(e)));
        if (added.length) {
          obs.autostartAlerted = true;
          added.forEach((e) => {
            alerts.push({
              source: 'newProgramWatch',
              severity: 'critical',
              title: 'New program added itself to startup',
              detail: `Since ${name} first ran, a new auto-start entry appeared: "${e.Name}" -> ${e.Command} (${e.Location}).`,
              time: new Date().toISOString(),
            });
          });
        }
      }

      if (Date.now() > obs.observeUntil) {
        observations.delete(lpath);
      }
    }
  }

  return { alerts };
}

module.exports = { check };
