# Watchtower

Watchtower watches a Windows PC for signs that someone else is using it or reaching into it. It looks for:

- remote sign-ins
- remote-control programs
- new programs that open ports, go online or add themselves to startup
- programs disguised as Windows files
- unexpected network connections
- camera and microphone use

It keeps a tamper-evident history of everything it sees. It isn't antivirus; it works alongside Microsoft Defender.

## How it's built

```
┌──────────────────────────── Windows PC ─────────────────────────────┐
│                                                                     │
│  Watchtower service (LocalSystem, starts at boot, no window)        │
│   ├─ ETW kernel session ── every process launch, TCP connect/accept │
│   ├─ Security log subscription ── sign-ins, failures, logoffs       │
│   ├─ Native snapshots ── TCP table, WTS sessions, camera/mic ledger,│
│   │                      startup items, services, Defender (WMI)    │
│   ├─ Watchtower.Core ── detection, plain-English alerts, trust,     │
│   │                     safety guards, hash-chained history         │
│   ├─ Updater ── signed manifest, staged rollout, auto-rollback      │
│   └─ Named pipe \\.\pipe\Watchtower.v1 (local users only)           │
│               ▲                                                     │
│               │ newline-delimited JSON RPC + pushed events          │
│               ▼                                                     │
│  Watchtower app (Electron, per user, tray + notifications)          │
│                                                                     │
│  %ProgramData%\Watchtower  (SYSTEM + Administrators only)           │
│    history\  state\  crashes\  updates\                             │
└─────────────────────────────────────────────────────────────────────┘
```

| Path | What it is |
|---|---|
| `src/Watchtower.Core` | Platform-neutral logic: alert catalog, history, trust rules, guards, detection trackers, exposure analysis, update manifests and rollout, RPC. Fully unit-tested. |
| `src/Watchtower.Service` | The Windows service: ETW and native Windows APIs, pipe server, updater, crash reporting. |
| `ui/` | The Electron app, a thin client of the service. |
| `installer/` | WiX MSI: installs the service (auto-start, restart on failure) and the app. |
| `tools/Watchtower.DevHost` | Stand-in service with simulated Windows data, for building and testing the UI on any OS. |
| `tools/Watchtower.ReleaseTool` | `wt-release`: signing keys, manifests and rollouts. |
| `tests/` | Core unit tests. UI tests live in `ui/test/`. |

## Building and testing

You need the .NET 10 SDK and Node 22.

```bash
dotnet test tests/Watchtower.Core.Tests        # core logic, any OS
dotnet build Watchtower.slnx                   # everything; the service cross-compiles on any OS

cd ui && npm ci && npm test                     # pipe client
dotnet build ../tools/Watchtower.DevHost
npm run test:e2e                                # real renderer + real pipe client + dev host, admin and standard user
```

To work on the UI without Windows, run `dotnet run --project tools/Watchtower.DevHost -- --fresh` (add `--standard-user` to see the read-only view). Then start the app, or run the E2E test for screenshots in `ui/test-results/`.

On Windows, from an elevated prompt:

```powershell
dotnet run --project src/Watchtower.Service -- --console              # run the service in a console
dotnet run --project src/Watchtower.Service -- --smoke-test 20        # checks ETW, signatures, pipe; exit code 0 = pass
dotnet publish src/Watchtower.Service -c Release -o artifacts/service -p:Version=0.2.0
(cd ui; npm ci; npm run pack)                                          # -> artifacts/ui/win-unpacked
dotnet build installer -c Release -p:Version=0.2.0                    # -> Watchtower.msi
```

CI (`.github/workflows/ci.yml`) runs all of this. The Windows job also installs the MSI, checks the service starts automatically and answers on its pipe, kills the service to confirm Windows restarts it, and uninstalls.

## Security model

- **Only the service has privileges.** The app runs as the signed-in user and asks the service to act.
- **The pipe is local and can't be impersonated.**
  - Network access to the pipe is denied.
  - Users can't create instances of it.
  - The service creates the first instance exclusively.
  - The caller's identity comes from their Windows token, never from anything they send.
- **Changing things needs an administrator account.**
  - Ending programs, blocking addresses, signing out sessions, removing startup items, trusting things and changing settings are "Act" methods.
  - Act methods require membership of Administrators; with UAC an unelevated admin still qualifies.
  - Standard users get a read-only view with an explanation.
- **Safety guards run in the service, not just the UI.**
  - Windows' critical processes (flagged critical by Windows, or core system files verified in place and signed by Microsoft) can't be ended.
  - Neither can Microsoft Defender or Watchtower itself.
  - The router, DNS servers, loopback and this PC's own addresses can't be blocked.
  - Windows Security's startup entries and services can't be removed.
  - Each refusal comes with a plain reason.
- **Targets come from the service's own view.** A startup item is removed by its key from the latest scan, and a process by a PID that's actually running. A client can't make SYSTEM delete an arbitrary file or registry value. History export returns content that the app writes as the user.
- **Data is locked down.** `%ProgramData%\Watchtower` is SYSTEM and Administrators only.
- **The history is tamper-evident.**
  - Every entry is hashed over all of its fields with a hand-rolled canonical encoder, so a runtime upgrade can't break verification.
  - Each entry is chained to the previous one.
  - A separate high-water mark catches deletion of the newest entries.
  - The service re-verifies the chain hourly and alerts on a break.
  - An off-machine backup keeps an untampered copy. It refuses to write through a link planted in the backup folder.
- **Gaps are detected.** A heartbeat lets the service tell apart a reboot (routine), an administrator stopping it (warning), and the process vanishing while the PC stayed up (urgent).
- **No outbound calls** except the update check and crash reports. Crash reports are off unless the user opts in during setup and the build has a Sentry DSN. Signature revocation is checked from cache only.

## Updates and safe rollout

A bad update to a security product can take down every machine it reaches; that's what happened with CrowdStrike in July 2024. Watchtower's update path is built so that can't happen quietly.

**On each PC**

1. **Signed, fresh, non-replayable manifest.** The manifest is signed with ECDSA P-256; several keys can be trusted at once, for rotation. It expires after 14 days, and a sequence number stops an older manifest being replayed. The signature is checked before the JSON is parsed.
2. **Staged rollout.** Each release has a rollout percentage. Each machine has a stable, per-release bucket, so a new build reaches 1% of machines before it reaches 100%. Customers pick a ring:
   - Early: gets releases as soon as a rollout starts.
   - Standard: gets them when the machine's bucket is reached.
   - Delayed: waits one week after 100%.
3. **Verified download.** The installer's size, SHA-256 and Authenticode publisher must all match.
4. **Health-gated install with automatic rollback.** Before the new version runs, the updater keeps the previous version's installer. The new version is on probation until it has run for 10 minutes. If it crashes on startup more than 3 times (Windows service recovery restarts it each time), the previous version is reinstalled automatically, and that version is never offered to this machine again. The check runs first thing in `Main`, so even a build that crashes during startup rolls back.
5. **Publisher kill switches.** `pause` stops one release. `halt` stops every rollout. `recall` blocks a version, and machines running it move to the newest fully rolled-out release, even if it's older.
6. **One channel.** Code and detection content (watchlists, catalogs) ship together in the one signed MSI. There's no separate fast content channel that could skip the staged rollout, which is how the CrowdStrike file got out.
7. **User mode only.** Watchtower has no kernel driver, so a bad build can crash Watchtower but not Windows.

**Release runbook**

```bash
wt-release keygen --out keys --key-id 2026a                    # once; store the key offline, add the public key to appsettings.json
wt-release add     --manifest manifest.json --msi Watchtower-1.2.0.msi --version 1.2.0 \
                   --url https://updates.example.com/Watchtower-1.2.0.msi --key keys/2026a.pem --key-id 2026a
wt-release rollout --manifest manifest.json --version 1.2.0 --percent 1   ...   # then 10, 50, 100
wt-release pause   --manifest manifest.json --version 1.2.0 ...               # stop if crash-free rate drops
wt-release recall  --manifest manifest.json --version 1.2.0 ...               # move affected machines off it
wt-release refresh --manifest manifest.json ...                               # at least weekly, before expiry
```

Upload `manifest.json` and `manifest.json.sig` to the URL in `appsettings.json`.

Widen a rollout only when the release's crash-free session rate in Sentry holds, for example at 99.9% or better. Early-ring and internal machines should get it first.

## User experience

- **Setup guide on first run.** It explains what Watchtower does, then asks:
  - which accounts may sign in remotely
  - which remote-control tools you use
  - whether to spend 24 hours learning what's normal
  - update timing
  - crash-report consent
  - an optional backup folder
- **Plain-English alerts.** Each alert has an urgency label (Urgent / Check / FYI), a one-line summary, and "What does this mean?" with an explanation and what to do. It also has the relevant action buttons.
  - The wording lives in one catalog: `src/Watchtower.Core/Alerts/AlertCatalog.cs`.
  - Only the summary is stored in history, so explanations can be improved without touching old records.
  - A test fails if any alert type is missing text.
- **Trust and Dismiss.** Trust stops alerting about a program, publisher, address, account or startup item. Publisher trust only counts when the signature is valid. Trusted events are still logged, marked as trusted, and each trust decision is itself logged with who made it. Dismiss hides an alert from the feed but keeps it in History.
- **Learning period.** Routine "first time" events are quiet for the first 24 hours. Serious ones never are.

## Limitations

- **Administrators can still stop it.** Anyone with administrator rights can stop or uninstall the service. Watchtower records the gap and alerts on it afterwards, but prevention would need a protected (ELAM-signed) service or a kernel driver. That's a different class of product with its own risks.
- **Connections are recorded, not contents.** Only TCP connect and accept events are real-time. UDP (including QUIC) isn't monitored.
- **Windows limits kernel trace sessions.** If another tool uses them all, Watchtower falls back to polling every few seconds and says so in the sidebar and the log.
- **Remote tools are matched by executable name.** A renamed tool is still caught as a new program that goes online or opens a port, but not as a "remote-control program".
- **The app doesn't verify the service's identity.** A process that squats the pipe name while the service is stopped could feed the app false data. The service itself refuses to start if the name is taken.
- **Signed isn't safe.** "Signed" and "unsigned" are signals, not verdicts.

## Before selling

- [ ] **Run CI on Windows and fix what it finds.** The service, the ETW integration, the MSI and the install/kill/uninstall test have been compiled but not yet run on a real Windows machine.
- [ ] **Code-signing certificate.** Add `SIGNING_CERT_BASE64` and `SIGNING_CERT_PASSWORD` to CI secrets. Also set `InstallerPublisher` to the certificate's subject name, because updates refuse installers that aren't signed by it.
- [ ] **Update hosting.** Choose an HTTPS host for the manifest and MSIs, generate keys with `wt-release keygen`, and fill in `UpdateManifestUrl` and `UpdateSigningKeys`.
- [ ] **Crash reporting.** Set up a Sentry project, set `SentryDsn`, and add a privacy notice covering crash reports.
- [ ] **WiX licence.** The installer pins WiX 5 (MS-RL). WiX 6+ binaries come with the Open Source Maintenance Fee EULA; decide before upgrading.
- [ ] **Product identity.** Pick the product name, `Manufacturer`, `ARPURLINFOABOUT` and an icon set (the tray icon is a 16×16 placeholder).
