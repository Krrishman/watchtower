const { exec } = require('child_process');

function run(cmd, { timeout = 10_000 } = {}) {
  return new Promise((resolve, reject) => {
    exec(
      cmd,
      { timeout, windowsHide: true, maxBuffer: 1024 * 1024 * 10 },
      (err, stdout, stderr) => {
        if (err) {
          reject(new Error(stderr?.trim() || err.message));
          return;
        }
        resolve(stdout);
      }
    );
  });
}

// Runs a block of PowerShell via -Command, wrapped so it always returns
// something parseable even when the pipeline produces zero results.
function runPowerShell(script, opts) {
  const escaped = script.replace(/"/g, '\\"');
  return run(`powershell -NoProfile -NonInteractive -Command "${escaped}"`, opts);
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
