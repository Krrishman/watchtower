const { runPowerShell } = require('./lib/exec');
const { loadJson, saveJson } = require('./lib/store');
const { FEATURES, APPS } = require('./debloatCatalog');

function psQuote(str) {
  return String(str).replace(/'/g, "''");
}

function friendlyError(message) {
  if (/access is denied|unauthorized|elevat|administrator|requires? admin/i.test(message)) {
    return `${message} — try closing Watchtower and reopening it with "Run as Administrator".`;
  }
  return message;
}

function regPath(hive, path) {
  return `${hive}:\\${path}`;
}

// ---------- Reading current state ----------

async function getRegistryStates() {
  const regFeatures = FEATURES.filter((f) => f.type === 'registry');
  if (!regFeatures.length) return {};
  const lines = regFeatures.map((f) => {
    const p = regPath(f.checkEntry.hive, f.checkEntry.path);
    return (
      `try { $r['${f.id}'] = (Get-ItemProperty -Path '${psQuote(p)}' -Name '${psQuote(f.checkEntry.name)}' -ErrorAction Stop).'${psQuote(f.checkEntry.name)}' } ` +
      `catch { $r['${f.id}'] = $null }`
    );
  });
  const script = `$r = @{}; ${lines.join('; ')}; $r | ConvertTo-Json -Compress`;
  const out = await runPowerShell(script, { timeout: 20_000 });
  let parsed = {};
  try {
    parsed = JSON.parse(out || '{}');
  } catch {
    parsed = {};
  }
  const states = {};
  regFeatures.forEach((f) => {
    const val = parsed[f.id];
    const target = f.entries.find(
      (e) => e.hive === f.checkEntry.hive && e.path === f.checkEntry.path && e.name === f.checkEntry.name
    );
    states[f.id] = val != null && String(val) === String(target.enableValue) ? 'on' : 'off';
  });
  return states;
}

async function getServiceStates() {
  const svcFeatures = FEATURES.filter((x) => x.type === 'service');
  if (!svcFeatures.length) return {};
  const lines = svcFeatures.map(
    (f) =>
      `try { $r['${f.id}'] = (Get-Service -Name '${psQuote(f.serviceName)}' -ErrorAction Stop).StartType.ToString() } ` +
      `catch { $r['${f.id}'] = 'unsupported' }`
  );
  const script = `$r = @{}; ${lines.join('; ')}; $r | ConvertTo-Json -Compress`;
  try {
    const out = await runPowerShell(script, { timeout: 20_000 });
    const parsed = JSON.parse(out || '{}');
    const states = {};
    svcFeatures.forEach((f) => {
      const v = parsed[f.id];
      states[f.id] = v === 'unsupported' || v == null ? 'unsupported' : v === 'Disabled' ? 'on' : 'off';
    });
    return states;
  } catch {
    const states = {};
    svcFeatures.forEach((f) => { states[f.id] = 'unsupported'; });
    return states;
  }
}

async function getScheduledTaskStates() {
  const taskFeatures = FEATURES.filter((x) => x.type === 'scheduledTasks');
  if (!taskFeatures.length) return {};
  const lines = taskFeatures.map(
    (f) =>
      `try { $t = @(Get-ScheduledTask -TaskPath '${psQuote(f.taskPath)}' -ErrorAction Stop); ` +
      `$r['${f.id}'] = @($t | Where-Object { $_.State -ne 'Disabled' }).Count } ` +
      `catch { $r['${f.id}'] = -1 }`
  );
  const script = `$r = @{}; ${lines.join('; ')}; $r | ConvertTo-Json -Compress`;
  try {
    const out = await runPowerShell(script, { timeout: 30_000 });
    const parsed = JSON.parse(out || '{}');
    const states = {};
    taskFeatures.forEach((f) => {
      const v = parsed[f.id];
      states[f.id] = v == null || v < 0 ? 'unsupported' : v === 0 ? 'on' : 'off';
    });
    return states;
  } catch {
    const states = {};
    taskFeatures.forEach((f) => { states[f.id] = 'unsupported'; });
    return states;
  }
}

async function getRecallState() {
  const feature = FEATURES.find((f) => f.type === 'recall');
  if (!feature) return {};
  try {
    const out = await runPowerShell(
      "(Get-WindowsOptionalFeature -Online -FeatureName Recall -ErrorAction Stop).State",
      { timeout: 20_000 }
    );
    const state = out.trim();
    return { [feature.id]: state === 'Disabled' ? 'on' : 'off' };
  } catch {
    return { [feature.id]: 'unsupported' };
  }
}

async function getFeatureStates() {
  const [reg, svc, tasks, recall] = await Promise.all([
    getRegistryStates().catch(() => ({})),
    getServiceStates().catch(() => ({})),
    getScheduledTaskStates().catch(() => ({})),
    getRecallState().catch(() => ({})),
  ]);
  return { ...reg, ...svc, ...tasks, ...recall };
}

async function getAppStates() {
  // One PowerShell spawn for all apps instead of one per app. Previously this
  // was a sequential loop — 13 spawns at ~0.5s each made the Debloat tab take
  // 8+ seconds to show anything.
  const checks = APPS.map((app) => {
    const expr = app.match
      .map((m) => `(Get-AppxPackage -Name '${psQuote(m)}' -ErrorAction SilentlyContinue)`)
      .join(' + ');
    return `$r['${app.id}'] = @(${expr}).Count`;
  });
  const script = `$r = @{}; ${checks.join('; ')}; $r | ConvertTo-Json -Compress`;

  try {
    const out = await runPowerShell(script, { timeout: 45_000 });
    const parsed = JSON.parse(out || '{}');
    const states = {};
    APPS.forEach((app) => {
      const count = parsed[app.id];
      states[app.id] = count == null ? 'unknown' : count > 0 ? 'installed' : 'removed';
    });
    return states;
  } catch {
    const states = {};
    APPS.forEach((app) => {
      states[app.id] = 'unknown';
    });
    return states;
  }
}

// ---------- Applying toggles ----------

async function setRegistryFeature(feature, enable) {
  const lines = feature.entries.map((e) => {
    const p = regPath(e.hive, e.path);
    if (enable) {
      return (
        `if (!(Test-Path '${psQuote(p)}')) { New-Item -Path '${psQuote(p)}' -Force | Out-Null }; ` +
        `Set-ItemProperty -Path '${psQuote(p)}' -Name '${psQuote(e.name)}' -Value ${e.enableValue} -Type ${e.type} -Force -ErrorAction Stop`
      );
    }
    return `Remove-ItemProperty -Path '${psQuote(p)}' -Name '${psQuote(e.name)}' -ErrorAction SilentlyContinue`;
  });
  await runPowerShell(lines.join('; '), { timeout: 20_000 });
}

async function setServiceFeature(feature, enable) {
  const key = `debloat-service-${feature.id}-prev-starttype`;
  if (enable) {
    const out = await runPowerShell(
      `(Get-Service -Name '${psQuote(feature.serviceName)}' -ErrorAction Stop).StartType`,
      { timeout: 10_000 }
    );
    saveJson(key, out.trim());
    await runPowerShell(
      `Stop-Service -Name '${psQuote(feature.serviceName)}' -Force -ErrorAction SilentlyContinue; ` +
        `Set-Service -Name '${psQuote(feature.serviceName)}' -StartupType Disabled -ErrorAction Stop`,
      { timeout: 15_000 }
    );
  } else {
    const prev = loadJson(key, 'Automatic');
    await runPowerShell(
      `Set-Service -Name '${psQuote(feature.serviceName)}' -StartupType ${prev} -ErrorAction Stop; ` +
        `Start-Service -Name '${psQuote(feature.serviceName)}' -ErrorAction SilentlyContinue`,
      { timeout: 15_000 }
    );
  }
}

async function setScheduledTasksFeature(feature, enable) {
  const cmdlet = enable ? 'Disable-ScheduledTask' : 'Enable-ScheduledTask';
  await runPowerShell(
    `Get-ScheduledTask -TaskPath '${psQuote(feature.taskPath)}' -ErrorAction Stop | ${cmdlet} -ErrorAction SilentlyContinue | Out-Null`,
    { timeout: 20_000 }
  );
}

async function setRecallFeature(enable) {
  const aiPolicy = {
    entries: [
      { hive: 'HKLM', path: 'SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsAI', name: 'DisableAIDataAnalysis', type: 'DWord', enableValue: 1 },
      { hive: 'HKLM', path: 'SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsAI', name: 'AllowRecallEnablement', type: 'DWord', enableValue: 0 },
    ],
  };
  if (enable) {
    await runPowerShell(
      'Disable-WindowsOptionalFeature -Online -FeatureName Recall -NoRestart -ErrorAction Stop | Out-Null',
      { timeout: 60_000 }
    );
    await setRegistryFeature(aiPolicy, true);
  } else {
    await setRegistryFeature(aiPolicy, false);
    await runPowerShell(
      'Enable-WindowsOptionalFeature -Online -FeatureName Recall -All -NoRestart -ErrorAction Stop | Out-Null',
      { timeout: 60_000 }
    );
  }
}

async function setFeature(id, enable) {
  const feature = FEATURES.find((f) => f.id === id);
  if (!feature) return { ok: false, error: 'Unknown feature' };
  try {
    if (feature.type === 'registry') await setRegistryFeature(feature, enable);
    else if (feature.type === 'service') await setServiceFeature(feature, enable);
    else if (feature.type === 'scheduledTasks') await setScheduledTasksFeature(feature, enable);
    else if (feature.type === 'recall') await setRecallFeature(enable);
    else return { ok: false, error: 'Unsupported feature type' };
    const needsRestart = feature.type === 'recall' || feature.id === 'bing-search';
    return { ok: true, note: needsRestart ? 'A sign-out or restart may be needed for this to fully take effect.' : undefined };
  } catch (err) {
    return { ok: false, error: friendlyError(err.message) };
  }
}

// ---------- Apps ----------

const APP_SNAPSHOT_KEY = 'debloat-app-snapshots';

async function setApp(id, install) {
  const app = APPS.find((a) => a.id === id);
  if (!app) return { ok: false, error: 'Unknown app' };

  if (!install) {
    try {
      const script = `@(${app.match
        .map((m) => `(Get-AppxPackage -AllUsers -Name '${psQuote(m)}' -ErrorAction SilentlyContinue)`)
        .join(' + ')}) | Select-Object PackageFullName,InstallLocation | ConvertTo-Json -Compress`;
      const out = await runPowerShell(script, { timeout: 20_000 });
      const parsed = JSON.parse(out || 'null');
      const rows = parsed == null ? [] : Array.isArray(parsed) ? parsed : [parsed];
      const snapshots = loadJson(APP_SNAPSHOT_KEY, {});
      snapshots[id] = rows;
      saveJson(APP_SNAPSHOT_KEY, snapshots);
    } catch {
      // Non-fatal — restore will just have nothing to work with later.
    }

    try {
      const removeScript = app.match
        .map(
          (m) =>
            `Get-AppxPackage -Name '${psQuote(m)}' -ErrorAction SilentlyContinue | Remove-AppxPackage -ErrorAction SilentlyContinue; ` +
            `Get-AppxProvisionedPackage -Online -ErrorAction SilentlyContinue | Where-Object { $_.PackageName -like '${psQuote(m)}' } | Remove-AppxProvisionedPackage -Online -ErrorAction SilentlyContinue | Out-Null`
        )
        .join('; ');
      await runPowerShell(removeScript, { timeout: 30_000 });
      return { ok: true };
    } catch (err) {
      return { ok: false, error: friendlyError(err.message) };
    }
  }

  // Restore: best-effort re-registration from the snapshot taken at removal time.
  const snapshots = loadJson(APP_SNAPSHOT_KEY, {});
  const saved = snapshots[id] || [];
  if (!saved.length) {
    return {
      ok: false,
      error: "No record of this app's install location — Windows may have cleaned it up already.",
      storeSearchTerm: app.storeSearchTerm,
    };
  }
  let restored = 0;
  for (const pkg of saved) {
    if (!pkg.InstallLocation) continue;
    try {
      await runPowerShell(
        `Add-AppxPackage -DisableDevelopmentMode -Register '${psQuote(pkg.InstallLocation)}\\AppxManifest.xml' -ErrorAction Stop`,
        { timeout: 20_000 }
      );
      restored += 1;
    } catch {
      // Files likely no longer present — fall through to the summary below.
    }
  }
  if (restored === 0) {
    return {
      ok: false,
      error: 'Windows already deleted the app files, so it can\'t be re-registered from disk.',
      storeSearchTerm: app.storeSearchTerm,
    };
  }
  return {
    ok: true,
    note:
      restored < saved.length
        ? 'Partially restored — some components may need reinstalling from the Store.'
        : undefined,
    storeSearchTerm: restored < saved.length ? app.storeSearchTerm : undefined,
  };
}

function getCatalog() {
  return {
    features: FEATURES.map(({ id, label, description }) => ({ id, label, description })),
    apps: APPS.map(({ id, label }) => ({ id, label })),
  };
}

module.exports = { getCatalog, getFeatureStates, getAppStates, setFeature, setApp };
