# Watchtower

A local desktop app that watches your own Windows machine for signs of
remote access, remote-control software, unusual outbound network
connections, camera/microphone use, newly-installed programs behaving
suspiciously, and basic system health — and keeps a persistent history
of all of it, not just a live feed.

This was scaffolded to get you a strong starting point, not a finished
security product. Read **Limitations** before relying on it.

## Requirements

- Windows 10 or 11
- [Node.js](https://nodejs.org) (LTS version)

## Setup

```bash
cd watchtower
npm install
npm start
```

For full coverage, right-click your terminal (or a shortcut to `npm start`)
and choose **Run as administrator**. Watchtower detects this at launch and
shows a banner if it's running unelevated, so you're never guessing. Without elevation, Windows won't let
the app read the Security event log, so login history, durations, and
failed-attempt alerts won't work — sessions, remote-tool detection,
network, camera/mic, process table, and new-program watching all still
work unelevated.

## Start at logon

**Settings > Start automatically** registers a scheduled task that launches
Watchtower at logon **with administrator rights**. This is deliberately not
Windows' normal startup-shortcut mechanism, which would start the app
unelevated and silently disable login history, session disconnect, firewall
blocks, and most debloat toggles on every boot. Creating the task requires
running Watchtower as Administrator once.

Without this on, anything that happens before you manually open the app is
never logged.

## Exporting history

**History > Export CSV / Export JSON** writes the *full* log (not just what's
on screen), honoring whichever source filter is active. CSV opens cleanly in
Excel. Useful if you ever need to hand the record to someone else.

## Tamper-evident history

Every history entry is hash-chained to the one before it and carries a
sequence number. **History > Verify integrity** walks the chain and reports
the first break it finds. This detects:

- an entry edited in place
- an entry deleted from the middle (sequence gap)
- the most recent entries deleted to hide activity (tracked via a separate
  high-water mark, since a truncated chain is otherwise self-consistent)

Exports include the sequence and hash so the record stays verifiable
outside the app.

**What this does and doesn't do:** it makes tampering *detectable*, not
*impossible*. Anyone with administrator rights can still rewrite the log —
they'd just have to forge the whole chain and the high-water file to do it
silently. Preventing tampering outright needs an append-only store off the
machine, which is why shipping a copy elsewhere (below) matters.

## Real-time process detection

Alongside interval polling, Watchtower subscribes to WMI
`Win32_ProcessStartTrace`, which fires on **every** process launch. This
closes the gap where a program could start and exit between two polls and
never be seen.

The **Real-time** indicator in the sidebar shows `live` when the
subscription is active and `polling` when it isn't. It requires
administrator rights; without them Watchtower falls back to polling and
says so rather than implying coverage it doesn't have.

## Network exposure

The **Exposure** tab answers "what can reach this machine from outside?"

The central distinction is what each listening port is **bound to**. A port on
`127.0.0.1` cannot be reached from another machine at all; one on `0.0.0.0` is
reachable from your whole network — and from the internet if your router
forwards it. The tab splits ports into those two groups rather than alarming
about everything that happens to be listening.

It also checks:

- **Adapter IPs** — flags a *public* IP sitting directly on an adapter, which
  means no router/NAT is shielding you and every open port faces the internet.
- **Firewall profiles** — Domain/Private/Public on or off, and default inbound action.
- **Remote Desktop** — enabled state, port, and whether Network Level
  Authentication is required. Without NLA, an unauthenticated attacker reaches
  the logon screen itself.
- **DNS servers** — DNS redirection silently sends you to fake sites.
- **Hosts file** — classic redirection vector; ad-blockers use it legitimately,
  so entries are shown for review rather than flagged as malicious.
- **Proxy settings** — a system proxy or auto-config URL you didn't set means
  something may be reading your web traffic.
- **Tunnel/VPN adapters** — active tunnels that don't match known VPN software
  are flagged, since an unexplained tunnel is a serious backdoor indicator.
- **SMB shares** — built-in administrative shares (`C$`, `ADMIN$`, `IPC$`) are
  marked as built-in rather than flagged; anything else you've shared is listed.

Buttons jump straight to the relevant Windows settings pages for RDP, firewall,
and proxy.

### What it deliberately doesn't do

- **No outbound calls.** Everything is read locally. Watchtower doesn't contact
  a third-party service to look up your public IP, so using it doesn't tell
  anyone else about your machine.
- **No external port scan.** Whether your *router* forwards a port to this
  machine can only be tested from outside your network. The tab tells you what
  this machine exposes; check your router's port-forwarding and UPnP settings
  separately for the rest.

## Off-machine backup

**Settings > Off-machine backup** mirrors the history log into a folder you
choose. Point it at a cloud-synced folder (OneDrive, Dropbox, Google Drive)
or a network share — then wiping this machine doesn't erase the record, and
the cloud service's own version history defeats an overwrite.

It syncs on a timer (5/15/60 min) and immediately after any **critical**
alert, debounced so an alert burst triggers one sync rather than a dozen.
Files land in `<folder>/watchtower-<hostname>/`, so several machines can
safely share one destination.

The anchor and high-water sidecar files are copied alongside the log, so
the off-machine copy stays independently verifiable — not just a blob of
text. Writes go to a temp name and are renamed into place, so a sync
interrupted partway can't leave a truncated log at the destination.

**This is the single most valuable security addition in the app.** The hash
chain tells you *if* your log was tampered with; an off-machine copy is what
gives you an untampered one to compare against.

## Running in the background

Closing the window **hides** Watchtower to the system tray rather than
quitting — monitoring and the history log keep running, which is the
whole point of a watcher. Use the tray icon to reopen it, or **Quit
(stops monitoring)** from the tray right-click menu to actually exit.

Data (history, baselines, known users, settings) is stored in
`%APPDATA%\Watchtower\store\` so it persists correctly in both `npm
start` and a packaged install.

## Tabs

- **Live Feed** — everything as it happens.
- **Processes** — every running process, whether it's digitally signed,
  and whether it currently has an active network connection, with a
  **Kill** button per process. Also lists active sessions with a
  **Disconnect** button for any RDP session. Signed isn't a guarantee of
  safety, and unsigned isn't proof of danger — lots of legitimate
  small/free software is unsigned — but it's a real signal worth
  knowing.
- **Network** — live outbound connections by process, with a **Block**
  button that adds a Windows Firewall rule for that address, and a
  manager for addresses you've already blocked.
- **History** — a persistent, filterable log of everything Watchtower
  has ever recorded, so you can check "did anything happen while I was
  away" even if you never watched the live feed. This only covers time
  the app was actually running.
- **Health Check** — shows current Windows Defender status, active
  Defender detections (with a button to jump into the native Windows
  Security app to remove them), a way to trigger a real quick scan, and
  Watchtower's own heuristic review of startup entries (removable with
  one click) and listening ports (killable with one click).
- **Debloat** — reversible on/off switches for Windows 11's telemetry,
  AI, and ad-personalization features, plus bundled apps you can
  uninstall and (best-effort) reinstall. See "Debloat toggles" below
  for exactly what each one does.
- **Settings** — a list of Windows account names you recognize. Any
  remote logon from a name not on this list is flagged as a critical
  "unrecognized user" alert instead of a routine notice.

## Debloat toggles

Every privacy/telemetry item is a genuine on/off switch — turning it on
applies the block via registry, a service, scheduled tasks, or a Windows
optional feature; turning it back off restores default Windows behavior
exactly. What's included:

- **Bing / web results in search** — local files and apps only, no web
  results or Copilot entry in Start/taskbar search.
- **Microsoft Copilot** — removes the taskbar button and blocks it by
  policy.
- **Widgets** — hides the taskbar icon.
- **Advertising ID** — stops apps from using it to personalize ads.
- **Tailored experiences** — stops Windows using diagnostic data for
  personalized tips/ads.
- **Activity History** — stops recording/uploading your app and file
  usage history.
- **Diagnostic data (telemetry) level** — sets it to the minimum Windows
  allows (Home/Pro can't reach a true zero; only Enterprise/Education can).
- **DiagTrack service** — the service that actually transmits most
  telemetry. Turning it back on restores whatever startup type it had
  before, not just a guessed default.
- **Customer Experience Improvement Program tasks** and **Application
  Experience tasks** — the scheduled tasks behind usage-stat collection
  and app-compatibility reporting.
- **Windows Recall** — disables the optional feature and blocks it by
  policy. Only shows as available on Copilot+ PCs with an NPU.

Bundled apps (Xbox suite, Solitaire, Clipchamp, To Do, Phone Link,
LinkedIn, Family Safety, News, Weather, Get Help, Tips, Feedback Hub,
and common social/streaming/game bloat) work the same switch-based way,
with one honest caveat: turning an app back on tries to re-register it
from where it was installed, which only works if Windows hasn't already
deleted those files. If that fails, the toggle tells you exactly what
happened and shows an **"Open in Microsoft Store"** button that jumps
straight to that app's search results so you can reinstall it in one
click — no need to go hunting for it yourself. Any toggle that fails
because Watchtower isn't elevated also says so directly and tells you
to reopen it as Administrator, rather than just showing a raw error.

## Taking action

Every remediation control is manual and one-at-a-time, with a
confirmation before it runs:

- **Kill process** — `taskkill /PID <id> /F`
- **Disconnect session** — `rwinsta <sessionId>` (forces a logoff)
- **Block address** — adds inbound + outbound Windows Firewall rules
  named `Watchtower Block <address>`; unblock removes them
- **Remove startup entry** — deletes the registry Run value or Startup
  shortcut, or disables (not deletes) a scheduled task
- **Defender detections** — Watchtower doesn't attempt to remove these
  itself; it opens the real Windows Security app so Defender's own
  (much more thoroughly tested) removal logic handles it

There's deliberately no "auto-clean everything flagged" button.
"Unsigned" and "has a listening port" are useful signals, not proof —
an automated cleaner acting on them alone could just as easily kill a
legitimate small program as an actual threat. You decide, item by item.

## What it watches

| Monitor | What it does | Source |
|---|---|---|
| Sessions | Flags any active RDP session | `query user` |
| Remote tools | Flags known remote-control software (TeamViewer, AnyDesk, VNC variants, etc.) starting up | process list |
| Event log | Logon/logoff history with duration, failed remote-logon attempts, unrecognized-user flagging, session reconnects | Security log, Event IDs 4624/4625/4634/4778/4779 |
| Network | Flags the first time a process connects to a given remote address | `Get-NetTCPConnection` |
| Camera / Mic | Flags new camera/mic use, including background apps | Windows' own access ledger in the registry |
| Processes | Full process table with signature status and live network use | `Win32_Process` + Authenticode |
| New program watch | Watches any never-before-seen executable for 5 minutes after its first run: does it open a listening port, call out to the network, or add itself to startup | process list + `Get-NetTCPConnection` + autostart snapshot diff |
| Health check | Windows Defender status/scan trigger, plus unsigned-autostart and unsigned-listening-process review | `Get-MpComputerStatus`, `Start-MpScan`, autostart snapshot, Authenticode |

## Limitations — read this

- **Process launches are caught in real time, but network activity still
  isn't.** WMI event subscription covers every process start; connections,
  camera/mic use, and sessions are still polled on 10–30s intervals, so
  brief network activity between polls can still be missed.
- **Watchtower cannot protect itself.** It runs in userspace with no
  self-defense: anything with administrator rights can kill the process,
  delete its startup task, or rewrite its files. The hash chain makes log
  tampering visible after the fact, but nothing here prevents a
  fully-compromised machine from disabling the monitor outright. That
  requires a kernel driver and a protected service — a different class of
  product.
- **The "Networked" column and new-program connection alerts lag by up
  to one network-poll cycle (20s)**, since they reuse the last network
  snapshot rather than re-querying. On the very first tick after
  startup they may show nothing at all until network data populates.
- **Some debloat toggles require Run as Administrator** (registry
  writes under HKLM, service startup-type changes, scheduled tasks,
  and the Recall optional feature all need elevation; per-user HKCU
  toggles like Bing search and Widgets work without it).
- **Restoring a removed app isn't always possible.** Windows doesn't
  guarantee it keeps an uninstalled app's files around, so "turn back
  on" is best-effort — it tells you directly if it couldn't restore
  something, with reinstalling from the Microsoft Store as the fallback.
- **Killing a process, disconnecting a session, or blocking an address
  requires the right privileges.** Some of these work unelevated;
  disconnecting another session and some firewall operations need Run
  as Administrator to succeed. Failures show the actual Windows error
  rather than failing silently.
- **This is not antivirus/EDR.** The process table, new-program watch,
  and health check give you real, useful signals — but they're
  heuristics built on public OS APIs, not a malware-detection engine.
  The Defender scan triggered from Health Check is the actual
  antivirus in this picture; treat Watchtower's own findings as "worth
  a look," not a verdict.
- **Network monitoring is connection-level, not content-level.** You'll
  see "this app connected to this address" or "this new program called
  out shortly after launch," not what data was sent. Seeing actual
  contents would require intercepting your own TLS traffic — a much
  bigger, more invasive project on its own.
- **"Signed" is a trust signal, not a verdict.** Plenty of legitimate
  indie/free software is unsigned. Plenty of malware is
  signed-then-revoked or uses a stolen certificate. Use it as one input,
  not the whole answer.
- **New-program watching only covers the first 5 minutes after first
  launch.** A program that waits longer than that before phoning home
  or adding persistence won't be caught by this specific feature (the
  network and autostart-diffing logic in Health Check can still catch
  it later, just without the "this just happened" framing).
- **First run will be noisy-then-quiet.** The network monitor and new
  program watch both silently learn your current baseline on the very
  first check, then alert on anything new after that. State lives in
  `store/*.json` — delete a file to reset that monitor's baseline.
- **4778/4779 session-reconnect events also fire for Fast User
  Switching**, not only RDP — treat those as "a session changed state,"
  not proof of remote access.
- **Login-history durations depend on the app running continuously.**
  If Watchtower isn't running when someone logs off, that entry never
  gets its duration filled in.
- **The remote-tool watchlist only catches names it knows.** It's editable
  in **Settings > Remote-tool watchlist** — add any tool the defaults miss,
  or disable a default that's noisy for you (e.g. `mstsc.exe` if you use
  Remote Desktop outbound yourself). A brand-new or renamed tool still won't
  be recognized until you add it.
- History (`store/history.jsonl`) and known-programs/network baselines
  persist across restarts; per-session "already alerted" state
  (sessions, watchlist processes, camera/mic) does not, so a still-
  running session may alert again after a restart.

## Packaging as an installable app

```bash
npm run dist
```

This uses `electron-builder` to produce a Windows installer in `dist/`.
