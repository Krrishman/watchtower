const { runPowerShell, psQuote } = require('./powershell');

// Bundled Store apps are installed per user, so removing and restoring them runs
// here, as the signed-in user, rather than in the SYSTEM service. This is a
// user-triggered action, not monitoring, so running PowerShell on demand is fine.
const APPS = [
  { id: 'xbox-suite', label: 'Xbox suite (app, Game Bar, overlay)', match: ['*Xbox*'], storeSearchTerm: 'Xbox' },
  { id: 'solitaire', label: 'Solitaire Collection', match: ['*SolitaireCollection*'], storeSearchTerm: 'Microsoft Solitaire Collection' },
  { id: 'clipchamp', label: 'Clipchamp (video editor)', match: ['*Clipchamp*'], storeSearchTerm: 'Clipchamp' },
  { id: 'todo', label: 'Microsoft To Do', match: ['*Todos*'], storeSearchTerm: 'Microsoft To Do' },
  { id: 'phone-link', label: 'Phone Link', match: ['*YourPhone*'], storeSearchTerm: 'Phone Link' },
  { id: 'linkedin', label: 'LinkedIn', match: ['*LinkedInforWindows*'], storeSearchTerm: 'LinkedIn' },
  { id: 'family-safety', label: 'Family Safety', match: ['*MicrosoftFamily*'], storeSearchTerm: 'Microsoft Family Safety' },
  { id: 'news', label: 'News', match: ['*BingNews*'], storeSearchTerm: 'Microsoft News' },
  { id: 'weather', label: 'Weather', match: ['*BingWeather*'], storeSearchTerm: 'MSN Weather' },
  { id: 'get-help', label: 'Get Help', match: ['*GetHelp*'], storeSearchTerm: 'Get Help' },
  { id: 'tips', label: 'Tips', match: ['*Getstarted*'], storeSearchTerm: 'Tips' },
  { id: 'feedback-hub', label: 'Feedback Hub', match: ['*WindowsFeedbackHub*'], storeSearchTerm: 'Feedback Hub' },
  {
    id: 'social-bloat',
    label: 'Preinstalled social, streaming and game apps (Facebook, Instagram, TikTok, Netflix, Disney+, Spotify, Candy Crush)',
    match: ['*Facebook*', '*Instagram*', '*TikTok*', '*Netflix*', '*Disney*', '*SpotifyMusic*', '*CandyCrush*', '*king.com*'],
    storeSearchTerm: null,
  },
];

const snapshots = new Map();

function catalog() {
  return APPS.map(({ id, label }) => ({ id, label }));
}

async function states() {
  const checks = APPS.map((app) => {
    const expr = app.match.map((m) => `(Get-AppxPackage -Name '${psQuote(m)}' -ErrorAction SilentlyContinue)`).join(' + ');
    return `$r['${app.id}'] = @(${expr}).Count`;
  });
  try {
    const out = await runPowerShell(`$r = @{}; ${checks.join('; ')}; $r | ConvertTo-Json -Compress`, { timeout: 45_000 });
    const parsed = JSON.parse(out || '{}');
    return Object.fromEntries(APPS.map((a) => [a.id, parsed[a.id] == null ? 'unknown' : parsed[a.id] > 0 ? 'installed' : 'removed']));
  } catch {
    return Object.fromEntries(APPS.map((a) => [a.id, 'unknown']));
  }
}

async function set(id, install) {
  const app = APPS.find((a) => a.id === id);
  if (!app) return { ok: false, error: 'Unknown app.' };

  if (!install) {
    try {
      const listing = await runPowerShell(
        `@(${app.match.map((m) => `(Get-AppxPackage -Name '${psQuote(m)}' -ErrorAction SilentlyContinue)`).join(' + ')}) | Select-Object PackageFullName,InstallLocation | ConvertTo-Json -Compress`
      );
      const parsed = JSON.parse(listing || 'null');
      snapshots.set(id, parsed == null ? [] : Array.isArray(parsed) ? parsed : [parsed]);
      await runPowerShell(app.match.map((m) => `Get-AppxPackage -Name '${psQuote(m)}' | Remove-AppxPackage -ErrorAction Stop`).join('; '));
      return { ok: true };
    } catch (err) {
      return { ok: false, error: err.message };
    }
  }

  const saved = snapshots.get(id) || [];
  let restored = 0;
  for (const pkg of saved) {
    if (!pkg.InstallLocation) continue;
    try {
      await runPowerShell(`Add-AppxPackage -DisableDevelopmentMode -Register '${psQuote(pkg.InstallLocation)}\\AppxManifest.xml' -ErrorAction Stop`);
      restored += 1;
    } catch {
      // Files already cleaned up by Windows; fall through to the Store link.
    }
  }
  if (restored === 0) {
    return { ok: false, error: "Windows has already cleaned up this app's files, so it has to be reinstalled from the Microsoft Store.", storeSearchTerm: app.storeSearchTerm };
  }
  return { ok: true };
}

module.exports = { catalog, states, set };
