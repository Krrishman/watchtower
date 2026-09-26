const fs = require('fs');
const os = require('os');
const path = require('path');
const { run } = require('./exec');

// Checks Authenticode signature status for a list of file paths in a single
// PowerShell invocation. Returns { [path]: 'Valid' | 'NotSigned' | 'HashMismatch'
// | 'UnknownError' | 'Unavailable' }. 'Valid' is the only status that means
// "signed by someone and the signature checks out" — everything else should
// be treated as unverified, not necessarily malicious.
async function checkSignatures(paths) {
  if (!paths.length) return {};

  const tmpFile = path.join(os.tmpdir(), `watchtower-sig-${Date.now()}-${Math.random().toString(36).slice(2)}.json`);
  fs.writeFileSync(tmpFile, JSON.stringify(paths), 'utf8');

  const script = (
    `$items = Get-Content -Raw '${tmpFile}' | ConvertFrom-Json; ` +
    '$items | ForEach-Object { ' +
    'try { ' +
    '$sig = Get-AuthenticodeSignature -LiteralPath $_ -ErrorAction Stop; ' +
    '[PSCustomObject]@{ Path = $_; Status = $sig.Status.ToString() } ' +
    '} catch { ' +
    '[PSCustomObject]@{ Path = $_; Status = "Unavailable" } ' +
    '} ' +
    '} | ConvertTo-Json -Compress'
  ).replace(/"/g, '\\"');

  let out;
  try {
    out = await run(`powershell -NoProfile -NonInteractive -Command "${script}"`, { timeout: 30_000 });
  } finally {
    fs.unlink(tmpFile, () => {});
  }

  let parsed;
  try {
    parsed = JSON.parse(out || '[]');
  } catch {
    return {};
  }
  const rows = Array.isArray(parsed) ? parsed : parsed ? [parsed] : [];
  const map = {};
  rows.forEach((r) => {
    map[r.Path] = r.Status;
  });
  return map;
}

module.exports = { checkSignatures };
