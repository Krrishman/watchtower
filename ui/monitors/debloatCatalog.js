// Every FEATURES entry is a reversible toggle backed by the registry, a
// service, scheduled tasks, or a Windows optional feature. "enabled" always
// means "the annoyance/telemetry is blocked" — turning a toggle off restores
// default Windows behavior.

const FEATURES = [
  {
    id: 'bing-search',
    label: 'Bing / web results in search',
    description: 'Removes Bing web results from Start menu and taskbar search — local files and apps only.',
    type: 'registry',
    checkEntry: { hive: 'HKCU', path: 'Software\\Policies\\Microsoft\\Windows\\Explorer', name: 'DisableSearchBoxSuggestions' },
    entries: [
      { hive: 'HKCU', path: 'Software\\Policies\\Microsoft\\Windows\\Explorer', name: 'DisableSearchBoxSuggestions', type: 'DWord', enableValue: 1 },
      { hive: 'HKLM', path: 'SOFTWARE\\Policies\\Microsoft\\Windows\\Explorer', name: 'DisableSearchBoxSuggestions', type: 'DWord', enableValue: 1 },
      { hive: 'HKCU', path: 'Software\\Microsoft\\Windows\\CurrentVersion\\Search', name: 'BingSearchEnabled', type: 'DWord', enableValue: 0 },
      { hive: 'HKCU', path: 'Software\\Microsoft\\Windows\\CurrentVersion\\Search', name: 'CortanaConsent', type: 'DWord', enableValue: 0 },
    ],
  },
  {
    id: 'copilot',
    label: 'Microsoft Copilot',
    description: 'Removes the Copilot taskbar button and blocks it by policy so it does not quietly come back after an update.',
    type: 'registry',
    checkEntry: { hive: 'HKLM', path: 'SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsCopilot', name: 'TurnOffWindowsCopilot' },
    entries: [
      { hive: 'HKLM', path: 'SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsCopilot', name: 'TurnOffWindowsCopilot', type: 'DWord', enableValue: 1 },
      { hive: 'HKCU', path: 'Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced', name: 'ShowCopilotButton', type: 'DWord', enableValue: 0 },
    ],
  },
  {
    id: 'widgets',
    label: 'Widgets',
    description: 'Hides the Widgets icon from the taskbar.',
    type: 'registry',
    checkEntry: { hive: 'HKCU', path: 'Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced', name: 'TaskbarDa' },
    entries: [
      { hive: 'HKCU', path: 'Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced', name: 'TaskbarDa', type: 'DWord', enableValue: 0 },
    ],
  },
  {
    id: 'advertising-id',
    label: 'Advertising ID',
    description: 'Stops apps from using your per-account advertising ID to personalize ads.',
    type: 'registry',
    checkEntry: { hive: 'HKCU', path: 'SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\AdvertisingInfo', name: 'Enabled' },
    entries: [
      { hive: 'HKCU', path: 'SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\AdvertisingInfo', name: 'Enabled', type: 'DWord', enableValue: 0 },
      { hive: 'HKLM', path: 'SOFTWARE\\Policies\\Microsoft\\Windows\\AdvertisingInfo', name: 'DisabledByGroupPolicy', type: 'DWord', enableValue: 1 },
    ],
  },
  {
    id: 'tailored-experiences',
    label: 'Tailored experiences',
    description: 'Stops Windows using your diagnostic data to personalize tips, ads, and recommendations.',
    type: 'registry',
    checkEntry: { hive: 'HKCU', path: 'Software\\Microsoft\\Windows\\CurrentVersion\\Privacy', name: 'TailoredExperiencesWithDiagnosticDataEnabled' },
    entries: [
      { hive: 'HKCU', path: 'Software\\Microsoft\\Windows\\CurrentVersion\\Privacy', name: 'TailoredExperiencesWithDiagnosticDataEnabled', type: 'DWord', enableValue: 0 },
    ],
  },
  {
    id: 'activity-history',
    label: 'Activity History',
    description: 'Stops Windows recording and uploading a history of the apps and files you use.',
    type: 'registry',
    checkEntry: { hive: 'HKLM', path: 'SOFTWARE\\Policies\\Microsoft\\Windows\\System', name: 'EnableActivityFeed' },
    entries: [
      { hive: 'HKLM', path: 'SOFTWARE\\Policies\\Microsoft\\Windows\\System', name: 'EnableActivityFeed', type: 'DWord', enableValue: 0 },
      { hive: 'HKLM', path: 'SOFTWARE\\Policies\\Microsoft\\Windows\\System', name: 'PublishUserActivities', type: 'DWord', enableValue: 0 },
      { hive: 'HKLM', path: 'SOFTWARE\\Policies\\Microsoft\\Windows\\System', name: 'UploadUserActivities', type: 'DWord', enableValue: 0 },
    ],
  },
  {
    id: 'telemetry-level',
    label: 'Diagnostic data (telemetry) level',
    description: "Sets diagnostic data collection to the minimum Windows allows. On Home/Pro this can't reach a true zero — only Enterprise/Education can go further.",
    type: 'registry',
    checkEntry: { hive: 'HKLM', path: 'SOFTWARE\\Policies\\Microsoft\\Windows\\DataCollection', name: 'AllowTelemetry' },
    entries: [
      { hive: 'HKLM', path: 'SOFTWARE\\Policies\\Microsoft\\Windows\\DataCollection', name: 'AllowTelemetry', type: 'DWord', enableValue: 0 },
      { hive: 'HKLM', path: 'SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\DataCollection', name: 'AllowTelemetry', type: 'DWord', enableValue: 0 },
    ],
  },
  {
    id: 'diagtrack-service',
    label: 'Connected User Experiences and Telemetry (DiagTrack)',
    description: 'The background service that transmits most telemetry. Turning this off stops it; turning it back on restores whatever startup type it had before.',
    type: 'service',
    serviceName: 'DiagTrack',
  },
  {
    id: 'ceip-tasks',
    label: 'Customer Experience Improvement Program tasks',
    description: 'Scheduled tasks that collect general usage statistics.',
    type: 'scheduledTasks',
    taskPath: '\\Microsoft\\Windows\\Customer Experience Improvement Program\\',
  },
  {
    id: 'app-experience-tasks',
    label: 'Application Experience tasks',
    description: 'Scheduled tasks (Compatibility Appraiser, ProgramDataUpdater) that send app-compatibility data Microsoft uses for Windows Update targeting.',
    type: 'scheduledTasks',
    taskPath: '\\Microsoft\\Windows\\Application Experience\\',
  },
  {
    id: 'recall',
    label: 'Windows Recall',
    description: 'Disables the Recall optional feature and blocks it by policy. Only present on Copilot+ PCs with an NPU — shows as "not available" everywhere else.',
    type: 'recall',
  },
];

// Bundled apps: "enabled" (installed) is the default state; toggling off
// uninstalls for the current user and de-provisions it so it won't reinstall
// for new profiles. Toggling back on attempts to re-register the app from
// its original install path — this only works if Windows hasn't deleted the
// underlying files yet, which isn't guaranteed. The UI reports this plainly.
const APPS = [
  { id: 'xbox-suite', label: 'Xbox suite (app, Game Bar, overlay)', match: ['*Xbox*'], storeSearchTerm: 'Xbox' },
  { id: 'solitaire', label: 'Solitaire Collection', match: ['*SolitaireCollection*'], storeSearchTerm: 'Microsoft Solitaire Collection' },
  { id: 'clipchamp', label: 'Clipchamp (video editor)', match: ['*Clipchamp*'], storeSearchTerm: 'Clipchamp' },
  { id: 'todo', label: 'Microsoft To Do', match: ['*Todos*'], storeSearchTerm: 'Microsoft To Do' },
  { id: 'phone-link', label: 'Phone Link', match: ['*YourPhone*'], storeSearchTerm: 'Phone Link' },
  { id: 'linkedin', label: 'LinkedIn', match: ['*LinkedInforWindows*'], storeSearchTerm: 'LinkedIn' },
  { id: 'family-safety', label: 'Family Safety', match: ['*MicrosoftFamily*'], storeSearchTerm: 'Microsoft Family Safety' },
  { id: 'news', label: 'News (MSN / Bing News)', match: ['*BingNews*'], storeSearchTerm: 'Microsoft News' },
  { id: 'weather', label: 'Weather (Bing Weather)', match: ['*BingWeather*'], storeSearchTerm: 'MSN Weather' },
  { id: 'get-help', label: 'Get Help', match: ['*GetHelp*'], storeSearchTerm: 'Get Help' },
  { id: 'tips', label: 'Tips / Get Started', match: ['*Getstarted*'], storeSearchTerm: 'Tips' },
  { id: 'feedback-hub', label: 'Feedback Hub', match: ['*WindowsFeedbackHub*'], storeSearchTerm: 'Feedback Hub' },
  {
    id: 'social-bloat',
    label: 'Social/streaming/game bloat (Facebook, Instagram, TikTok, Netflix, Disney+, Spotify, Candy Crush)',
    match: ['*Facebook*', '*Instagram*', '*TikTok*', '*Netflix*', '*Disney*', '*SpotifyMusic*', '*CandyCrush*', '*king.com*'],
    storeSearchTerm: null, // bundle of several unrelated apps — no single search term applies
  },
];

module.exports = { FEATURES, APPS };
