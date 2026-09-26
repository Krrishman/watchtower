const { runPowerShell } = require('./exec');

let cache = null;
let cacheTime = 0;
const TTL_MS = 5000; // several monitors poll this within the same few seconds

function toArray(parsed) {
  if (parsed == null) return [];
  return Array.isArray(parsed) ? parsed : [parsed];
}

async function getProcessDetails({ fresh = false } = {}) {
  const now = Date.now();
  if (!fresh && cache && now - cacheTime < TTL_MS) return cache;

  const out = await runPowerShell(
    'Get-CimInstance Win32_Process | ' +
      'Select-Object ProcessId,Name,ExecutablePath,CommandLine | ' +
      'ConvertTo-Json -Compress'
  );
  const rows = toArray(JSON.parse(out || '[]'));
  cache = rows.map((r) => ({
    pid: r.ProcessId,
    name: r.Name,
    path: r.ExecutablePath || null,
    commandLine: r.CommandLine || null,
  }));
  cacheTime = now;
  return cache;
}

module.exports = { getProcessDetails };
