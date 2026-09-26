const { run, runPowerShell } = require('./lib/exec');
const { checkSignatures } = require('./lib/signature');
const { getProcessDetails } = require('./lib/processes');
const { loadJson, saveJson } = require('./lib/store');
const { snapshotAutostart } = require('./autostart');

const SIG_CACHE_KEY = 'signature-cache'; // shared with processTable.js on purpose

const SUSPECT_DIRS = [/\\temp\\/i, /\\appdata\\local\\temp\\/i, /\\downloads\\/i];

function extractExePath(command) {
  if (!command) return null;
  const quoted = command.match(/^"([^"]+)"/);
  if (quoted) return quoted[1];
  return command.split(/\s+/)[0] || null;
}

async function getDefenderStatus() {
  try {
    const out = await runPowerShell(
      'Get-MpComputerStatus | Select-Object AntivirusEnabled,RealTimeProtectionEnabled,' +
        'AntivirusSignatureLastUpdated,QuickScanEndTime,FullScanEndTime | ConvertTo-Json -Compress',
      { timeout: 15_000 }
    );
    return JSON.parse(out || '{}');
  } catch (err) {
    return { unavailable: true, message: err.message };
  }
}

async function startQuickScan() {
  try {
    // Fired off detached so the UI isn't blocked for the several minutes a
    // quick scan typically takes; check progress later via getDefenderStatus().
    await run(
      'powershell -NoProfile -NonInteractive -Command ' +
        '"Start-Process powershell -WindowStyle Hidden -ArgumentList \'-NoProfile\',\'-Command\',\'Start-MpScan -ScanType QuickScan\'"',
      { timeout: 15_000 }
    );
    return { started: true };
  } catch (err) {
    return { started: false, error: err.message };
  }
}

async function runHeuristics() {
  const [autostart, listening, procs] = await Promise.all([
    snapshotAutostart().catch(() => []),
    runPowerShell(
      'Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue | ' +
        'Select-Object LocalPort,OwningProcess | ConvertTo-Json -Compress'
    )
      .then((out) => {
        const parsed = JSON.parse(out || 'null');
        return parsed == null ? [] : Array.isArray(parsed) ? parsed : [parsed];
      })
      .catch(() => []),
    getProcessDetails({ fresh: true }).catch(() => []),
  ]);

  const sigCache = loadJson(SIG_CACHE_KEY, {});

  // Resolve + sign-check autostart entries.
  const autostartPaths = [
    ...new Set(autostart.map((e) => extractExePath(e.Command)).filter((p) => p && !(p in sigCache))),
  ];
  if (autostartPaths.length) {
    Object.assign(sigCache, await checkSignatures(autostartPaths));
  }

  const autostartFindings = autostart
    .map((e) => {
      const exePath = extractExePath(e.Command);
      const status = exePath ? sigCache[exePath] || 'Unknown' : 'Unknown';
      const inSuspectDir = SUSPECT_DIRS.some((re) => re.test(e.Command || ''));
      const worthReview = status !== 'Valid' || inSuspectDir;
      return { ...e, signatureStatus: status, inSuspectDir, worthReview };
    })
    .filter((f) => f.worthReview);

  // Resolve + sign-check processes with a listening port.
  const pidToProc = new Map(procs.map((p) => [p.pid, p]));
  const listeningPaths = [
    ...new Set(
      listening
        .map((l) => pidToProc.get(l.OwningProcess)?.path)
        .filter((p) => p && !(p in sigCache))
    ),
  ];
  if (listeningPaths.length) {
    Object.assign(sigCache, await checkSignatures(listeningPaths));
  }

  const listeningFindings = listening
    .map((l) => {
      const proc = pidToProc.get(l.OwningProcess);
      const status = proc?.path ? sigCache[proc.path] || 'Unknown' : 'Unknown';
      return {
        port: l.LocalPort,
        pid: l.OwningProcess,
        name: proc?.name || `pid:${l.OwningProcess}`,
        path: proc?.path || null,
        signatureStatus: status,
        worthReview: status !== 'Valid',
      };
    })
    .filter((f) => f.worthReview);

  saveJson(SIG_CACHE_KEY, sigCache);

  return { autostartFindings, listeningFindings };
}

async function getThreatDetections() {
  try {
    const out = await runPowerShell(
      'Get-MpThreatDetection -ErrorAction Stop | ' +
        'Select-Object ThreatID,ProcessName,Resources,InitialDetectionTime | ConvertTo-Json -Compress',
      { timeout: 15_000 }
    );
    const parsed = JSON.parse(out || 'null');
    return parsed == null ? [] : Array.isArray(parsed) ? parsed : [parsed];
  } catch {
    return [];
  }
}

async function runFullCheck() {
  const [defender, heuristics, scan, threats] = await Promise.all([
    getDefenderStatus(),
    runHeuristics(),
    startQuickScan(),
    getThreatDetections(),
  ]);
  return { defender, scan, threats, ...heuristics, ranAt: new Date().toISOString() };
}

module.exports = { getDefenderStatus, startQuickScan, runHeuristics, runFullCheck, getThreatDetections };
