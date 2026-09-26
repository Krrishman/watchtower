const { exec, execFile } = require('child_process');

function settle(resolve, reject) {
  return (err, stdout, stderr) => {
    if (err) {
      reject(new Error(stderr?.trim() || err.message));
      return;
    }
    resolve(stdout);
  };
}

const EXEC_OPTS = { windowsHide: true, maxBuffer: 1024 * 1024 * 10 };

function run(cmd, { timeout = 10_000 } = {}) {
  return new Promise((resolve, reject) => {
    exec(cmd, { ...EXEC_OPTS, timeout }, settle(resolve, reject));
  });
}

// Scripts embed machine-controlled strings (registry names, file paths). Going
// through cmd.exe would let a crafted `"` break out of quoting and run commands
// with Watchtower's (often elevated) rights, so PowerShell is launched directly
// and the script is passed base64-encoded, never parsed by a shell.
function runPowerShell(script, { timeout = 10_000 } = {}) {
  const encoded = Buffer.from(script, 'utf16le').toString('base64');
  return new Promise((resolve, reject) => {
    execFile(
      'powershell',
      ['-NoProfile', '-NonInteractive', '-EncodedCommand', encoded],
      { ...EXEC_OPTS, timeout },
      settle(resolve, reject)
    );
  });
}

// Long-running PowerShell that streams output back line by line. exec() buffers
// until exit, which never happens for an event subscription, so streaming needs
// spawn instead.
function spawnPowerShell(script) {
  const { spawn } = require('child_process');
  return spawn(
    'powershell',
    ['-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-Command', script],
    { windowsHide: true }
  );
}

module.exports = { run, runPowerShell, spawnPowerShell };
