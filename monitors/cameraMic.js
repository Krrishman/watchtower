const { runPowerShell } = require('./lib/exec');

// Windows keeps a real access log for camera/mic under this registry root,
// with one leaf key per app (packaged apps directly, classic desktop apps
// under a NonPackaged\ subfolder). LastUsedTimeStart/Stop are FILETIME
// values (100ns ticks since 1601-01-01); Stop == 0 means still in use.
const SCRIPT = `
function Get-Leaves($base) {
  Get-ChildItem -Path $base -Recurse -ErrorAction SilentlyContinue | ForEach-Object {
    $p = Get-ItemProperty -Path $_.PSPath -ErrorAction SilentlyContinue
    if ($p.PSObject.Properties.Name -contains 'LastUsedTimeStart') {
      [PSCustomObject]@{
        Key = $_.PSChildName
        Start = $p.LastUsedTimeStart
        Stop = $p.LastUsedTimeStop
      }
    }
  }
}
$webcam = @(Get-Leaves 'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\CapabilityAccessManager\\ConsentStore\\webcam')
$mic = @(Get-Leaves 'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\CapabilityAccessManager\\ConsentStore\\microphone')
@{ webcam = $webcam; microphone = $mic } | ConvertTo-Json -Compress -Depth 5
`;

const lastStart = new Map(); // key: `${device}|${appKey}` -> last Start value seen

function prettyAppName(key) {
  return key.includes('#') ? key.replace(/#/g, '\\') : key;
}

async function check() {
  const out = await runPowerShell(SCRIPT.replace(/\r?\n/g, ' '));
  let parsed;
  try {
    parsed = JSON.parse(out || '{}');
  } catch {
    parsed = {};
  }

  const alerts = [];
  const snapshot = [];

  for (const [device, list] of [
    ['webcam', parsed.webcam],
    ['microphone', parsed.microphone],
  ]) {
    const entries = Array.isArray(list) ? list : list ? [list] : [];
    for (const entry of entries) {
      if (!entry.Start) continue;
      const trackKey = `${device}|${entry.Key}`;
      const appName = prettyAppName(entry.Key);
      const stillActive = !entry.Stop || Number(entry.Stop) === 0;

      snapshot.push({ device, app: appName, active: stillActive });

      if (lastStart.get(trackKey) !== entry.Start) {
        lastStart.set(trackKey, entry.Start);
        alerts.push({
          source: 'cameraMic',
          severity: stillActive ? 'critical' : 'info',
          title: `${device === 'webcam' ? 'Camera' : 'Microphone'} accessed`,
          detail: `${appName} used the ${device}${stillActive ? ' and may still be using it' : ''}.`,
          time: new Date().toISOString(),
        });
      }
    }
  }

  return { alerts, snapshot };
}

module.exports = { check };
