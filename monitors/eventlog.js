const { runPowerShell } = require('./lib/exec');
const { loadJson } = require('./lib/store');

// 4624/4625 = successful/failed logon (filtered to LogonType 10, remote
// interactive). 4634 = logoff (used to close out a tracked remote session
// and compute how long it lasted). 4778/4779 = RDP/Fast-User-Switching
// session reconnect/disconnect. Reading the Security log normally requires
// an elevated (Run as Administrator) process, or membership in
// "Event Log Readers".
const LOOKBACK_SECONDS = 50;
const processed = new Set();
let warnedAboutAccess = false;

// logonId -> { account, startIso, startedAt }. Only populated from
// successful *remote* (type 10) logons, so a plain 4634 for some unrelated
// service/local logon never matches and is correctly ignored.
const openSessions = new Map();

function buildScript() {
  return (
    `$start = (Get-Date).AddSeconds(-${LOOKBACK_SECONDS}); ` +
    "try { " +
    "$e = Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4624,4625,4634,4778,4779; StartTime=$start} -ErrorAction Stop | " +
    'Select-Object Id, RecordId, TimeCreated, Message; ' +
    ',$e | ConvertTo-Json -Compress -Depth 3 ' +
    '} catch { ' +
    "if ($_.Exception.Message -match 'No events were found') { '[]' } " +
    "else { '{\"error\":\"' + ($_.Exception.Message -replace '\"', \"'\") + '\"}' } " +
    '}'
  );
}

function extractLogonType(message) {
  const m = message.match(/Logon Type:\s*(\d+)/i);
  return m ? Number(m[1]) : null;
}

function extractAccount(message) {
  const matches = [...message.matchAll(/Account Name:\s*([^\r\n]+)/gi)];
  if (!matches.length) return 'unknown user';
  return matches[matches.length - 1][1].trim();
}

function extractLogonId(message) {
  const matches = [...message.matchAll(/Logon ID:\s*(0x[0-9a-fA-F]+)/gi)];
  if (!matches.length) return null;
  return matches[matches.length - 1][1].toLowerCase();
}

function isKnownUser(account) {
  const known = loadJson('known-users', []);
  if (!known.length) return null; // caller treats null as "not configured yet"
  return known.some((u) => u.toLowerCase() === account.toLowerCase());
}

function formatDuration(ms) {
  const mins = Math.round(ms / 60000);
  if (mins < 1) return 'under a minute';
  if (mins < 60) return `${mins} min`;
  const hrs = Math.floor(mins / 60);
  return `${hrs}h ${mins % 60}m`;
}

async function check() {
  const out = await runPowerShell(buildScript());
  let parsed;
  try {
    parsed = JSON.parse(out || '[]');
  } catch {
    return { alerts: [] };
  }

  if (parsed && parsed.error) {
    const alerts = [];
    if (!warnedAboutAccess) {
      warnedAboutAccess = true;
      alerts.push({
        source: 'eventlog',
        severity: 'info',
        title: 'Security log unavailable',
        detail:
          'Cannot read the Security event log (needs Run as Administrator). ' +
          'Remote-logon, login-history, and session-reconnect alerts are limited without it.',
        time: new Date().toISOString(),
      });
    }
    return { alerts };
  }

  const events = Array.isArray(parsed) ? parsed : parsed ? [parsed] : [];
  const alerts = [];

  for (const evt of events) {
    const dedupeKey = `${evt.Id}:${evt.RecordId}`;
    if (processed.has(dedupeKey)) continue;
    processed.add(dedupeKey);

    const message = evt.Message || '';
    const account = extractAccount(message);
    const logonId = extractLogonId(message);

    if (evt.Id === 4624 || evt.Id === 4625) {
      const logonType = extractLogonType(message);
      if (logonType !== 10) continue; // not a remote interactive logon

      if (evt.Id === 4625) {
        alerts.push({
          source: 'eventlog',
          severity: 'critical',
          title: 'Failed remote logon attempt',
          detail: `Someone tried to log in remotely as "${account}" and failed, at ${evt.TimeCreated}.`,
          time: new Date().toISOString(),
          meta: { type: 'login_failed', account },
        });
        continue;
      }

      // Successful remote logon — open a ledger entry and check the
      // known-users allowlist.
      if (logonId) {
        openSessions.set(logonId, { account, startIso: evt.TimeCreated, startedAt: Date.now() });
      }
      const known = isKnownUser(account);
      let severity = 'warn';
      let title = 'Remote logon';
      if (known === false) {
        severity = 'critical';
        title = 'Unrecognized user logged in remotely';
      } else if (known === null) {
        title = 'Remote logon (no known-users list configured)';
      } else {
        title = 'Remote logon (recognized user)';
      }
      alerts.push({
        source: 'eventlog',
        severity,
        title,
        detail: `"${account}" logged in remotely at ${evt.TimeCreated}.`,
        time: new Date().toISOString(),
        meta: { type: 'login', account, logonId, startIso: evt.TimeCreated },
      });
    } else if (evt.Id === 4634) {
      if (!logonId || !openSessions.has(logonId)) continue; // not a tracked remote session
      const session = openSessions.get(logonId);
      openSessions.delete(logonId);
      const durationMs = Date.now() - session.startedAt;
      alerts.push({
        source: 'eventlog',
        severity: 'info',
        title: 'Remote session ended',
        detail: `"${session.account}" logged off after ${formatDuration(durationMs)} (started ${session.startIso}).`,
        time: new Date().toISOString(),
        meta: { type: 'logout', account: session.account, logonId, durationMs },
      });
    } else if (evt.Id === 4778 || evt.Id === 4779) {
      alerts.push({
        source: 'eventlog',
        severity: 'warn',
        title: evt.Id === 4778 ? 'Session reconnected' : 'Session disconnected',
        detail: `${account} — session ${evt.Id === 4778 ? 'reconnected' : 'disconnected'} at ${evt.TimeCreated} (can be RDP or fast user switching).`,
        time: new Date().toISOString(),
      });
    }
  }

  // Keep the dedupe set from growing forever.
  if (processed.size > 2000) {
    [...processed].slice(0, 1000).forEach((k) => processed.delete(k));
  }

  return { alerts };
}

module.exports = { check };
