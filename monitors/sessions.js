const { run } = require('./lib/exec');

// Sessions we've already told the user about, so we only alert once per
// session, not on every poll while it stays connected.
const knownActive = new Set();

function parseQuser(output) {
  const lines = output.split(/\r?\n/).filter((l) => l.trim().length);
  if (lines.length < 2) return [];

  // `query user` is fixed-width, not delimiter-separated. Splitting on runs of
  // spaces breaks on DISCONNECTED sessions, where SESSIONNAME is blank and the
  // ID column shifts left into its place — which previously made us read the
  // STATE column as the session ID. Slicing by the header's column offsets is
  // the only parse that survives a blank column.
  const header = lines[0];
  const idx = {
    user: header.indexOf('USERNAME'),
    session: header.indexOf('SESSIONNAME'),
    id: header.indexOf('ID'),
    state: header.indexOf('STATE'),
  };

  // Localized Windows won't have these English headers; fall back to
  // whitespace splitting and only trust rows that clearly have all columns.
  if (idx.user < 0 || idx.session < 0 || idx.id < 0 || idx.state < 0) {
    return lines
      .slice(1)
      .map((line) => {
        const parts = line.replace(/^>/, '').trim().split(/\s{2,}/).filter(Boolean);
        if (parts.length < 6) return null; // ambiguous row — don't guess
        return { username: parts[0], sessionName: parts[1], id: parts[2], state: parts[3] };
      })
      .filter(Boolean);
  }

  // The ID column is right-aligned under its header, so read from the end of
  // SESSIONNAME to the end of ID rather than from the header offset.
  return lines
    .slice(1)
    .map((line) => {
      const padded = line.padEnd(header.length + 20, ' ');
      const username = padded.slice(idx.user, idx.session).replace(/^>/, '').trim();
      const sessionName = padded.slice(idx.session, idx.id).trim();
      const id = padded.slice(idx.id, idx.state).trim();
      const state = padded.slice(idx.state).trim().split(/\s{2,}/)[0] || '';
      if (!username || !/^\d+$/.test(id)) return null;
      return { username, sessionName, id, state };
    })
    .filter(Boolean);
}

async function check() {
  const alerts = [];
  let rows = [];
  try {
    const output = await run('query user');
    rows = parseQuser(output);
  } catch (err) {
    // "No User exists for *" is the normal message when nobody is
    // interactively logged on to any session yet — not a real error.
    if (!/No User exists/i.test(err.message)) throw err;
  }

  const currentIds = new Set();
  for (const row of rows) {
    const sessionKey = `${row.username}:${row.sessionName}:${row.id}`;
    currentIds.add(sessionKey);
    const isRemote = /^rdp-tcp/i.test(row.sessionName);
    if (isRemote && !knownActive.has(sessionKey)) {
      alerts.push({
        source: 'sessions',
        severity: 'critical',
        title: 'Remote Desktop session active',
        detail: `User "${row.username}" is logged in over RDP (session ${row.sessionName}).`,
        time: new Date().toISOString(),
      });
    }
    knownActive.add(sessionKey);
  }

  // Drop sessions that have disconnected so a later reconnect re-alerts.
  for (const key of [...knownActive]) {
    if (!currentIds.has(key)) knownActive.delete(key);
  }

  return {
    alerts,
    snapshot: rows.map((r) => ({ ...r, remote: /^rdp-tcp/i.test(r.sessionName) })),
  };
}

module.exports = { check };
