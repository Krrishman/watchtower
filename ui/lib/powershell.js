const { execFile } = require('child_process');

// Scripts embed strings from the system (package names, paths). Passing them base64-
// encoded straight to powershell.exe means no shell ever parses them, so a crafted
// name can't break out and run commands.
function runPowerShell(script, { timeout = 30_000 } = {}) {
  const encoded = Buffer.from(script, 'utf16le').toString('base64');
  return new Promise((resolve, reject) => {
    execFile(
      'powershell.exe',
      ['-NoProfile', '-NonInteractive', '-EncodedCommand', encoded],
      { timeout, windowsHide: true, maxBuffer: 10 * 1024 * 1024 },
      (err, stdout, stderr) => (err ? reject(new Error((stderr || '').trim() || err.message)) : resolve(stdout))
    );
  });
}

function psQuote(value) {
  return String(value).replace(/'/g, "''");
}

module.exports = { runPowerShell, psQuote };
