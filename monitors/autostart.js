const { runPowerShell } = require('./lib/exec');

const SCRIPT = `
$results = @();
$runKeys = @(
  'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run',
  'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce',
  'HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run',
  'HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce'
);
foreach ($k in $runKeys) {
  $props = Get-ItemProperty -Path $k -ErrorAction SilentlyContinue;
  if ($props) {
    $props.PSObject.Properties | Where-Object { $_.Name -notmatch '^PS' } | ForEach-Object {
      $results += [PSCustomObject]@{ Location = $k; Name = $_.Name; Command = [string]$_.Value };
    }
  }
}
$startupFolders = @([Environment]::GetFolderPath('Startup'), [Environment]::GetFolderPath('CommonStartup'));
foreach ($f in $startupFolders) {
  Get-ChildItem -Path $f -ErrorAction SilentlyContinue | ForEach-Object {
    $results += [PSCustomObject]@{ Location = $f; Name = $_.Name; Command = $_.FullName };
  }
}
Get-ScheduledTask -ErrorAction SilentlyContinue | Where-Object { $_.TaskPath -notmatch '^\\\\Microsoft\\\\' -and $_.State -ne 'Disabled' } | ForEach-Object {
  $actions = ($_.Actions | ForEach-Object { "$($_.Execute) $($_.Arguments)" }) -join '; ';
  $results += [PSCustomObject]@{ Location = 'ScheduledTask'; Name = "$($_.TaskPath)$($_.TaskName)"; Command = $actions };
}
$results | ConvertTo-Json -Compress -Depth 3
`;

async function snapshotAutostart() {
  const out = await runPowerShell(SCRIPT.replace(/\r?\n/g, ' '), { timeout: 25_000 });
  let parsed;
  try {
    parsed = JSON.parse(out || '[]');
  } catch {
    return [];
  }
  return Array.isArray(parsed) ? parsed : parsed ? [parsed] : [];
}

module.exports = { snapshotAutostart };
