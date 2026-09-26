const path = require('path');
const { app } = require('electron');
const { runPowerShell } = require('./lib/exec');

const TASK_NAME = 'WatchtowerAutoStart';

function psQuote(str) {
  return String(str).replace(/'/g, "''");
}

// Returns { command, args } for however this app is currently running.
// In a packaged build that's the .exe directly; in dev it's electron.exe
// pointed at the project folder.
function launchTarget() {
  if (app.isPackaged) {
    return { command: process.execPath, args: '' };
  }
  return { command: process.execPath, args: `"${app.getAppPath()}"` };
}

async function isEnabled() {
  try {
    const out = await runPowerShell(
      `$t = Get-ScheduledTask -TaskName '${psQuote(TASK_NAME)}' -ErrorAction SilentlyContinue; if ($t) { 'yes' } else { 'no' }`,
      { timeout: 15_000 }
    );
    return out.trim() === 'yes';
  } catch {
    return false;
  }
}

// Registers a logon-triggered task running with the highest available
// privileges. This is deliberately NOT app.setLoginItemSettings(): that starts
// the app unelevated, which would silently disable login-history monitoring,
// session disconnect, firewall blocks, and most debloat toggles on every boot.
async function enable() {
  const { command, args } = launchTarget();
  const script = [
    `$action = New-ScheduledTaskAction -Execute '${psQuote(command)}'${args ? ` -Argument '${psQuote(args)}'` : ''}`,
    '$trigger = New-ScheduledTaskTrigger -AtLogOn',
    '$principal = New-ScheduledTaskPrincipal -UserId $env:USERNAME -LogonType InteractiveToken -RunLevel Highest',
    '$settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -ExecutionTimeLimit ([TimeSpan]::Zero)',
    `Register-ScheduledTask -TaskName '${psQuote(TASK_NAME)}' -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Force -ErrorAction Stop | Out-Null`,
  ].join('; ');

  try {
    await runPowerShell(script, { timeout: 30_000 });
    return { ok: true, note: 'Watchtower will start automatically at logon, with administrator rights.' };
  } catch (err) {
    const msg = /access is denied|unauthorized|denied/i.test(err.message)
      ? `${err.message} — creating an elevated startup task requires running Watchtower as Administrator first.`
      : err.message;
    return { ok: false, error: msg };
  }
}

async function disable() {
  try {
    await runPowerShell(
      `Unregister-ScheduledTask -TaskName '${psQuote(TASK_NAME)}' -Confirm:$false -ErrorAction Stop`,
      { timeout: 20_000 }
    );
    return { ok: true };
  } catch (err) {
    return { ok: false, error: err.message };
  }
}

module.exports = { isEnabled, enable, disable, TASK_NAME };
