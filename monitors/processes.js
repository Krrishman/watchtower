const { run } = require('./lib/exec');
const { loadJson } = require('./lib/store');

// Lowercased executable names for common remote-access / remote-control
// software. Users can extend this at runtime via Settings — see WATCHLIST().
const DEFAULT_WATCHLIST = [
  'teamviewer.exe', 'teamviewer_service.exe',
  'anydesk.exe',
  'vncserver.exe', 'winvnc.exe', 'tvnserver.exe', 'uvnc_service.exe', 'ultravnc.exe', 'winvnc4.exe',
  'rutserv.exe', 'rfusclient.exe', // Remote Utilities
  'aeroadmin.exe',
  'supremo.exe', 'supremohelper.exe',
  'ammyy.exe', 'ammyyadmin.exe',
  'showmypc.exe',
  'g2mcomm.exe', 'g2mupdate.exe', 'g2svc.exe', // GoToMyPC / GoToMeeting
  'lmiguardiansvc.exe', 'lmiignition.exe', // LogMeIn
  'remoting_host.exe', 'remotingdesktophost.exe', // Chrome Remote Desktop
  'splashtopstreamer.exe', 'srserver.exe', 'srfeature.exe', // Splashtop
  'screenconnect.windowsclient.exe', 'connectwisecontrol.clienthost.exe',
  'dwservice.exe', 'dwagent.exe',
  'radmin.exe', 'rserver3.exe',
  'mstsc.exe', // built-in RDP client — flags outbound RDP connections too
];

// Re-read on every check so edits in Settings take effect immediately
// without restarting the app.
function WATCHLIST() {
  const custom = loadJson('custom-watchlist', []);
  const removed = new Set(loadJson('watchlist-disabled', []).map((n) => n.toLowerCase()));
  const merged = [...DEFAULT_WATCHLIST, ...custom.map((n) => String(n).toLowerCase())];
  return new Set(merged.filter((n) => !removed.has(n)));
}

function getWatchlistInfo() {
  const removed = new Set(loadJson('watchlist-disabled', []).map((n) => n.toLowerCase()));
  return {
    defaults: DEFAULT_WATCHLIST.map((n) => ({ name: n, disabled: removed.has(n) })),
    custom: loadJson('custom-watchlist', []).map((n) => String(n).toLowerCase()),
  };
}

const seenPids = new Set();

function parseTasklistCsv(output) {
  return output
    .split(/\r?\n/)
    .filter((l) => l.startsWith('"'))
    .map((line) => {
      const fields = line.split('","').map((f) => f.replace(/^"|"$/g, ''));
      const [name, pid] = fields;
      return { name, pid };
    });
}

async function check() {
  const output = await run('tasklist /FO CSV /NH');
  const rows = parseTasklistCsv(output);
  const watchlist = WATCHLIST();
  const alerts = [];
  const currentPids = new Set();
  const flagged = [];

  for (const row of rows) {
    currentPids.add(row.pid);
    const lname = (row.name || '').toLowerCase();
    if (watchlist.has(lname)) {
      flagged.push(row);
      if (!seenPids.has(row.pid)) {
        alerts.push({
          source: 'processes',
          severity: 'warn',
          title: 'Remote-access tool running',
          detail: `${row.name} started (PID ${row.pid}).`,
          time: new Date().toISOString(),
        });
      }
    }
  }

  for (const pid of [...seenPids]) {
    if (!currentPids.has(pid)) seenPids.delete(pid);
  }
  flagged.forEach((r) => seenPids.add(r.pid));

  return { alerts, snapshot: flagged };
}

module.exports = { check, getWatchlistInfo };
