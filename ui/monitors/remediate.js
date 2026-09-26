const { run, runPowerShell } = require('./lib/exec');

function psQuote(str) {
  return String(str).replace(/'/g, "''");
}

function friendlyError(message) {
  if (/access is denied|unauthorized|elevat|administrator|requires? admin/i.test(message)) {
    return `${message} — try closing Watchtower and reopening it with "Run as Administrator".`;
  }
  return message;
}


async function killProcess(pid) {
  try {
    await run(`taskkill /PID ${Number(pid)} /F`);
    return { ok: true };
  } catch (err) {
    return { ok: false, error: friendlyError(err.message) };
  }
}

async function disconnectSession(sessionId) {
  try {
    // rwinsta forcibly resets/logs off the session. Requires an elevated
    // (Run as Administrator) process for sessions other than your own.
    await run(`rwinsta ${Number(sessionId)}`);
    return { ok: true };
  } catch (err) {
    return { ok: false, error: friendlyError(err.message) };
  }
}

const FW_PREFIX = 'Watchtower Block';

async function blockAddress(address) {
  const name = `${FW_PREFIX} ${address}`;
  const script =
    `New-NetFirewallRule -DisplayName '${psQuote(name)}' -Direction Outbound -RemoteAddress '${psQuote(address)}' -Action Block -ErrorAction Stop | Out-Null; ` +
    `New-NetFirewallRule -DisplayName '${psQuote(name)} (in)' -Direction Inbound -RemoteAddress '${psQuote(address)}' -Action Block -ErrorAction Stop | Out-Null`;
  try {
    await runPowerShell(script, { timeout: 15_000 });
    return { ok: true };
  } catch (err) {
    return { ok: false, error: friendlyError(err.message) };
  }
}

async function unblockAddress(address) {
  const name = `${FW_PREFIX} ${address}`;
  const script =
    `Get-NetFirewallRule -DisplayName '${psQuote(name)}*' -ErrorAction SilentlyContinue | Remove-NetFirewallRule -ErrorAction SilentlyContinue`;
  try {
    await runPowerShell(script, { timeout: 15_000 });
    return { ok: true };
  } catch (err) {
    return { ok: false, error: friendlyError(err.message) };
  }
}

async function listBlockedAddresses() {
  const script =
    `Get-NetFirewallRule -DisplayName '${psQuote(FW_PREFIX)}*' -ErrorAction SilentlyContinue | ` +
    'Select-Object DisplayName | ConvertTo-Json -Compress';
  try {
    const out = await runPowerShell(script, { timeout: 15_000 });
    const parsed = JSON.parse(out || 'null');
    const rows = parsed == null ? [] : Array.isArray(parsed) ? parsed : [parsed];
    const addresses = new Set(
      rows.map((r) => r.DisplayName.replace(FW_PREFIX, '').replace('(in)', '').trim())
    );
    return [...addresses];
  } catch {
    return [];
  }
}

// entry: { Location, Name, Command } as produced by autostart.js
async function removeAutostartEntry(entry) {
  try {
    if (/^HK(CU|LM):/i.test(entry.Location)) {
      const script = `Remove-ItemProperty -Path '${psQuote(entry.Location)}' -Name '${psQuote(entry.Name)}' -ErrorAction Stop`;
      await runPowerShell(script, { timeout: 15_000 });
      return { ok: true, action: 'removed registry value' };
    }

    if (entry.Location === 'ScheduledTask') {
      const idx = entry.Name.lastIndexOf('\\');
      const taskPath = entry.Name.slice(0, idx + 1) || '\\';
      const taskName = entry.Name.slice(idx + 1);
      const script = `Disable-ScheduledTask -TaskName '${psQuote(taskName)}' -TaskPath '${psQuote(taskPath)}' -ErrorAction Stop | Out-Null`;
      await runPowerShell(script, { timeout: 15_000 });
      return { ok: true, action: 'disabled scheduled task' };
    }

    // Startup-folder shortcut — Command holds the full file path.
    const script = `Remove-Item -LiteralPath '${psQuote(entry.Command)}' -Force -ErrorAction Stop`;
    await runPowerShell(script, { timeout: 15_000 });
    return { ok: true, action: 'deleted startup shortcut' };
  } catch (err) {
    return { ok: false, error: friendlyError(err.message) };
  }
}

module.exports = {
  killProcess,
  disconnectSession,
  blockAddress,
  unblockAddress,
  listBlockedAddresses,
  removeAutostartEntry,
};
