const feed = document.getElementById('feed');
const feedEmpty = document.getElementById('feedEmpty');
const statusDot = document.getElementById('statusDot');
const statusText = document.getElementById('statusText');
const toggleBtn = document.getElementById('toggleBtn');

let monitoring = true;
// Cumulative alert counts for sources that don't have a richer live snapshot.
const alertCounts = { eventlog: 0, newProgramWatch: 0 };

function escapeHtml(str) {
  const div = document.createElement('div');
  div.textContent = str ?? '';
  return div.innerHTML;
}

function setRail(source, value, flagged) {
  const el = document.getElementById(`count-${source}`);
  const item = document.querySelector(`.rail-item[data-source="${source}"]`);
  if (el) el.textContent = value;
  if (item) item.classList.toggle('flagged', !!flagged);
}

function renderAlertRow(alert) {
  const el = document.createElement('div');
  el.className = `alert ${alert.severity}`;
  const time = new Date(alert.time).toLocaleTimeString([], {
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
  });
  el.innerHTML = `
    <div class="alert-time">${time}</div>
    <div class="alert-body">
      <div class="alert-title">${escapeHtml(alert.title)}</div>
      <div class="alert-detail">${escapeHtml(alert.detail)}</div>
    </div>
    <div class="alert-source">${escapeHtml(alert.source)}</div>
  `;
  return el;
}

function addAlert(alert) {
  feedEmpty.style.display = 'none';
  feed.prepend(renderAlertRow(alert));

  if (alert.source in alertCounts) {
    alertCounts[alert.source] += 1;
    setRail(alert.source, alertCounts[alert.source], alertCounts[alert.source] > 0);
  }
}

window.watchAPI.onAlert(addAlert);

window.watchAPI.onStatus(({ monitoring: on }) => {
  monitoring = on;
  statusDot.classList.toggle('on', on);
  statusText.textContent = on ? 'Monitoring' : 'Paused';
  toggleBtn.textContent = on ? 'Pause' : 'Resume';
});

window.watchAPI.onMonitorError(({ key, message }) => {
  addAlert({
    source: key,
    severity: 'info',
    title: `${key} check failed`,
    detail: message,
    time: new Date().toISOString(),
  });
});

toggleBtn.addEventListener('click', () => {
  if (monitoring) window.watchAPI.stop();
  else window.watchAPI.start();
});

// ---------- Elevation state ----------
const elevationBanner = document.getElementById('elevationBanner');
const railNote = document.getElementById('railNote');

function applyElevation(isElevated) {
  if (isElevated) {
    elevationBanner.classList.add('hidden');
    railNote.textContent =
      'Running as Administrator — all monitors and debloat toggles are available.';
  } else {
    elevationBanner.textContent =
      'Not running as Administrator. Login history, session disconnect, firewall blocks, and most debloat toggles will fail. Close Watchtower and reopen it with "Run as administrator" for full coverage.';
    elevationBanner.classList.remove('hidden');
    railNote.textContent =
      'Limited mode: no Security-log access, so no login history or durations.';
  }
}

window.watchAPI.onElevation(({ isElevated }) => applyElevation(isElevated));window.watchAPI.getElevation().then((v) => {
  if (v !== null && v !== undefined) applyElevation(v);
});

// Real-time process monitoring indicator
window.watchAPI.onProcessEvents(({ active, reason }) => {
  if (active) {
    setRail('processEvents', 'live', false);
  } else {
    setRail('processEvents', 'polling', true);
    if (reason) {
      addAlert({
        source: 'processEvents',
        severity: 'info',
        title: 'Real-time process monitoring unavailable',
        detail: `${reason} — falling back to interval polling, which can miss very short-lived processes. This usually needs Run as Administrator.`,
        time: new Date().toISOString(),
      });
    }
  }
});

// ---------- Tabs ----------
document.querySelectorAll('.tab').forEach((btn) => {
  btn.addEventListener('click', () => {
    document.querySelectorAll('.tab').forEach((b) => b.classList.remove('active'));
    document.querySelectorAll('.panel').forEach((p) => p.classList.add('hidden'));
    btn.classList.add('active');
    document.getElementById(`panel-${btn.dataset.tab}`).classList.remove('hidden');
    if (btn.dataset.tab === 'history') loadHistory();
    if (btn.dataset.tab === 'settings') loadKnownUsers();
    if (btn.dataset.tab === 'health') loadDefenderStatusOnly();
    if (btn.dataset.tab === 'network') loadBlockedAddresses();
    if (btn.dataset.tab === 'debloat') loadDebloat();
    if (btn.dataset.tab === 'exposure') loadExposureIfEmpty();
  });
});

// ---------- Sessions (rail count + mini table with disconnect) ----------
const sessionsTableBody = document.getElementById('sessionsTableBody');

function renderSessionsTable(rows) {
  sessionsTableBody.innerHTML = rows.length
    ? rows
        .map(
          (r) => `<tr>
            <td>${escapeHtml(r.username)}</td>
            <td>${escapeHtml(r.sessionName)}</td>
            <td>${r.remote ? '<span class="tag unsigned">RDP</span>' : '<span class="tag yes">local</span>'}</td>
            <td>${r.remote ? `<button class="action-btn danger" data-disconnect="${r.id}">Disconnect</button>` : ''}</td>
          </tr>`
        )
        .join('')
    : '<tr><td colspan="4" style="font-family: var(--sans); color: var(--muted);">No sessions reported yet.</td></tr>';

  sessionsTableBody.querySelectorAll('button[data-disconnect]').forEach((btn) => {
    btn.addEventListener('click', async () => {
      if (!confirm('Forcibly disconnect this session? The user will be logged off.')) return;
      btn.disabled = true;
      const result = await window.watchAPI.disconnectSession(btn.dataset.disconnect);
      if (!result.ok) alert(`Could not disconnect: ${result.error}`);
    });
  });
}

window.watchAPI.onSnapshot('sessions', (rows) => {
  const remote = rows.filter((r) => r.remote).length;
  setRail('sessions', remote, remote > 0);
  renderSessionsTable(rows);
});

window.watchAPI.onSnapshot('processes', (rows) => {
  setRail('processes', rows.length, rows.length > 0);
});

window.watchAPI.onSnapshot('cameraMic', (rows) => {
  const active = rows.filter((r) => r.active).length;
  setRail('cameraMic', active > 0 ? `${active} active` : rows.length, active > 0);
});

// ---------- Processes tab ----------
const processTableBody = document.getElementById('processTableBody');
window.watchAPI.onSnapshot('processTable', (rows) => {
  processTableBody.innerHTML = rows
    .map((r) => {
      const signedTag = r.signed
        ? '<span class="tag yes">signed</span>'
        : `<span class="tag unsigned">${escapeHtml(r.signatureStatus)}</span>`;
      const netTag = r.networked
        ? '<span class="tag yes">yes</span>'
        : '<span class="tag no">no</span>';
      return `<tr>
        <td>${escapeHtml(r.name)}</td>
        <td>${r.pid}</td>
        <td>${signedTag}</td>
        <td>${netTag}</td>
        <td title="${escapeHtml(r.path)}">${escapeHtml(r.path)}</td>
        <td><button class="action-btn danger" data-kill="${r.pid}">Kill</button></td>
      </tr>`;
    })
    .join('');

  processTableBody.querySelectorAll('button[data-kill]').forEach((btn) => {
    btn.addEventListener('click', async () => {
      if (!confirm('Force-quit this process? Unsaved work in it will be lost.')) return;
      btn.disabled = true;
      const result = await window.watchAPI.killProcess(btn.dataset.kill);
      if (!result.ok) alert(`Could not kill process: ${result.error}`);
    });
  });
});

// ---------- Network tab ----------
const networkTableBody = document.getElementById('networkTableBody');
const blockedList = document.getElementById('blockedList');

window.watchAPI.onSnapshot('network', (rows) => {
  const newCount = rows.filter((r) => r.isNew).length;
  setRail('network', rows.length, newCount > 0);

  networkTableBody.innerHTML = rows.length
    ? rows
        .map(
          (r) => `<tr>
            <td>${escapeHtml(r.process)}</td>
            <td>${escapeHtml(r.remoteAddress)}</td>
            <td>${r.remotePort}</td>
            <td>${r.isNew ? '<span class="tag unsigned">new</span>' : ''}</td>
            <td><button class="action-btn danger" data-block="${escapeHtml(r.remoteAddress)}">Block</button></td>
          </tr>`
        )
        .join('')
    : '<tr><td colspan="5" style="font-family: var(--sans); color: var(--muted);">No active connections reported yet.</td></tr>';

  networkTableBody.querySelectorAll('button[data-block]').forEach((btn) => {
    btn.addEventListener('click', async () => {
      const addr = btn.dataset.block;
      if (!confirm(`Block all traffic to/from ${addr} with a Windows Firewall rule?`)) return;
      btn.disabled = true;
      const result = await window.watchAPI.blockAddress(addr);
      if (!result.ok) alert(`Could not block: ${result.error}`);
      else loadBlockedAddresses();
    });
  });
});

async function loadBlockedAddresses() {
  const addresses = await window.watchAPI.listBlockedAddresses();
  blockedList.innerHTML = addresses.length
    ? addresses
        .map(
          (a) =>
            `<li><span>${escapeHtml(a)}</span><button data-unblock="${escapeHtml(a)}">Unblock</button></li>`
        )
        .join('')
    : '<li style="color: var(--muted); font-family: var(--sans);">Nothing blocked yet.</li>';

  blockedList.querySelectorAll('button[data-unblock]').forEach((btn) => {
    btn.addEventListener('click', async () => {
      await window.watchAPI.unblockAddress(btn.dataset.unblock);
      loadBlockedAddresses();
    });
  });
}

// ---------- History tab ----------
const historyList = document.getElementById('historyList');
const historyFilter = document.getElementById('historyFilter');

async function loadHistory() {
  const source = historyFilter.value || undefined;
  const entries = await window.watchAPI.getHistory({ limit: 300, source });
  historyList.innerHTML = '';
  if (!entries.length) {
    historyList.innerHTML = '<div class="feed-empty">Nothing logged yet for this filter.</div>';
    return;
  }
  entries.forEach((e) => historyList.appendChild(renderAlertRow(e)));
}

historyFilter.addEventListener('change', loadHistory);

document.getElementById('exportCsvBtn').addEventListener('click', () => exportHistory('csv'));
document.getElementById('exportJsonBtn').addEventListener('click', () => exportHistory('json'));

const verifyBtn = document.getElementById('verifyBtn');
const integrityBar = document.getElementById('integrityBar');

verifyBtn.addEventListener('click', async () => {
  verifyBtn.disabled = true;
  verifyBtn.textContent = 'Verifying…';
  try {
    const r = await window.watchAPI.verifyHistory();
    integrityBar.className = 'integrity-bar ' + (r.ok ? 'ok' : r.unverifiable ? 'warn' : 'bad');
    integrityBar.textContent = (r.ok ? '✓ ' : '⚠ ') + r.message;
  } catch (err) {
    integrityBar.className = 'integrity-bar bad';
    integrityBar.textContent = `Verification failed: ${err.message}`;
  } finally {
    verifyBtn.disabled = false;
    verifyBtn.textContent = 'Verify integrity';
  }
});

async function exportHistory(format) {
  // Exports the full history, honoring the current source filter.
  const source = historyFilter.value || null;
  const result = await window.watchAPI.exportHistory({ format, source });
  if (result.canceled) return;
  if (result.ok) {
    alert(`Exported ${result.count} entries to:\n${result.filePath}`);
  } else {
    alert(`Export failed: ${result.error}`);
  }
}

// ---------- Health check tab ----------
const runHealthBtn = document.getElementById('runHealthBtn');
const healthResults = document.getElementById('healthResults');

function renderHealthReport(report) {
  const d = report.defender || {};
  const defenderBlock = d.unavailable
    ? `<div class="health-row">Windows Defender status unavailable (${escapeHtml(d.message || 'unknown reason')}) — you may be running a different antivirus.</div>`
    : `<div class="health-row">Real-time protection: ${d.RealTimeProtectionEnabled ? 'ON' : 'OFF'} · Signatures updated: ${escapeHtml(d.AntivirusSignatureLastUpdated || 'unknown')} · Last quick scan: ${escapeHtml(d.QuickScanEndTime || 'never')}</div>`;

  const scanLine = report.scan
    ? report.scan.started
      ? '<div class="health-row">Quick scan launched in the background — check back here in a few minutes for updated scan times.</div>'
      : `<div class="health-row">Could not start a scan: ${escapeHtml(report.scan.error || 'unknown error')}</div>`
    : '';

  const threats = report.threats || [];
  const threatsBlock = threats.length
    ? `<div class="health-block"><h4>Defender has active detections</h4>${threats
        .map(
          (t) =>
            `<div class="health-row critical">${escapeHtml(t.ProcessName || 'Unknown process')} — detected ${escapeHtml(t.InitialDetectionTime || '')}</div>`
        )
        .join('')}<div class="health-row-actions"><button class="action-btn danger" id="openSecurityBtn">Open Windows Security to remove</button></div></div>`
    : '';

  const autostart = (report.autostartFindings || [])
    .map(
      (f, i) =>
        `<div class="health-row" data-autostart-idx="${i}">${escapeHtml(f.Name)} — ${escapeHtml(f.Command)}<br>${escapeHtml(f.signatureStatus)}${f.inSuspectDir ? ' · runs from a Temp/Downloads-style folder' : ''}
          <div class="health-row-actions"><button class="action-btn danger" data-remove-autostart="${i}">Remove from startup</button></div>
        </div>`
    )
    .join('') || '<div class="feed-empty">Nothing unsigned or unusual found in startup items.</div>';

  const listening = (report.listeningFindings || [])
    .map(
      (f) =>
        `<div class="health-row">${escapeHtml(f.name)} (PID ${f.pid}) listening on port ${f.port} — ${escapeHtml(f.signatureStatus)}
          <div class="health-row-actions"><button class="action-btn danger" data-kill-listen="${f.pid}">Kill process</button></div>
        </div>`
    )
    .join('') || '<div class="feed-empty">No unsigned processes are listening for inbound connections.</div>';

  healthResults.innerHTML = `
    <div class="health-block"><h4>Windows Defender</h4>${defenderBlock}${scanLine}</div>
    ${threatsBlock}
    <div class="health-block"><h4>Startup items worth reviewing</h4>${autostart}</div>
    <div class="health-block"><h4>Unsigned processes with a listening port</h4>${listening}</div>
  `;

  const openBtn = document.getElementById('openSecurityBtn');
  if (openBtn) openBtn.addEventListener('click', () => window.watchAPI.openWindowsSecurity());

  healthResults.querySelectorAll('button[data-remove-autostart]').forEach((btn) => {
    btn.addEventListener('click', async () => {
      const entry = (report.autostartFindings || [])[Number(btn.dataset.removeAutostart)];
      if (!entry) return;
      if (!confirm(`Remove "${entry.Name}" from startup? This won't uninstall the program, just stop it launching automatically.`)) return;
      btn.disabled = true;
      const result = await window.watchAPI.removeAutostartEntry(entry);
      if (!result.ok) alert(`Could not remove: ${result.error}`);
      else btn.closest('.health-row').style.opacity = '0.4';
    });
  });

  healthResults.querySelectorAll('button[data-kill-listen]').forEach((btn) => {
    btn.addEventListener('click', async () => {
      if (!confirm('Force-quit this process?')) return;
      btn.disabled = true;
      const result = await window.watchAPI.killProcess(btn.dataset.killListen);
      if (!result.ok) alert(`Could not kill process: ${result.error}`);
    });
  });
}

async function loadDefenderStatusOnly() {
  if (healthResults.dataset.hasReport) return; // don't clobber a full report already shown
  const status = await window.watchAPI.getDefenderStatus();
  renderHealthReport({ defender: status, scan: null });
}

runHealthBtn.addEventListener('click', async () => {
  runHealthBtn.disabled = true;
  runHealthBtn.textContent = 'Running…';
  healthResults.innerHTML = '<div class="feed-empty">Checking Defender status, startup items, and listening ports…</div>';
  try {
    const report = await window.watchAPI.runHealthCheck();
    healthResults.dataset.hasReport = 'true';
    renderHealthReport(report);
  } catch (err) {
    healthResults.innerHTML = `<div class="feed-empty">Health check failed: ${escapeHtml(err.message)}</div>`;
  } finally {
    runHealthBtn.disabled = false;
    runHealthBtn.textContent = 'Run Health Check';
  }
});

// ---------- Settings tab (known users) ----------
const knownUsersList = document.getElementById('knownUsersList');
const newUserInput = document.getElementById('newUserInput');
const addUserBtn = document.getElementById('addUserBtn');

function renderKnownUsers(list) {
  knownUsersList.innerHTML = list.length
    ? list
        .map(
          (u) =>
            `<li><span>${escapeHtml(u)}</span><button data-user="${escapeHtml(u)}">Remove</button></li>`
        )
        .join('')
    : '<li style="color: var(--muted); font-family: var(--sans);">No known users added yet — every remote logon will show as "no known-users list configured" until you add at least one.</li>';

  knownUsersList.querySelectorAll('button[data-user]').forEach((btn) => {
    btn.addEventListener('click', async () => {
      const updated = await window.watchAPI.removeKnownUser(btn.dataset.user);
      renderKnownUsers(updated);
    });
  });
}

async function loadKnownUsers() {
  renderKnownUsers(await window.watchAPI.getKnownUsers());
  loadAutostart();
  loadWatchlist();
  loadOffsite();
}

// ---------- Off-machine backup ----------
const offsiteRow = document.getElementById('offsiteRow');

function renderOffsite(s) {
  const dest = s.destination
    ? escapeHtml(s.destination)
    : '<span style="color: var(--muted);">No folder chosen yet</span>';
  const last = s.lastSync
    ? `Last synced ${new Date(s.lastSync).toLocaleString()}`
    : 'Never synced';
  const err = s.lastError
    ? `<div class="toggle-row-note error" style="display:block;">${escapeHtml(s.lastError)}</div>`
    : '';

  offsiteRow.innerHTML = `
    <div class="toggle-row">
      <div class="toggle-row-text">
        <div class="toggle-row-label">Mirror history off this machine</div>
        <div class="toggle-row-desc">Syncs on a timer, and immediately after any critical alert.</div>
        <div class="toggle-row-note" style="display:none;"></div>
      </div>
      <label class="switch">
        <input type="checkbox" id="offsiteToggle" ${s.enabled ? 'checked' : ''} ${s.destination ? '' : 'disabled'} />
        <span class="switch-track"></span>
      </label>
    </div>
    <div class="health-row" style="border-left-color: var(--teal);">
      <div style="margin-bottom:6px;">${dest}</div>
      <div style="color: var(--muted); font-size: 11.5px;">${escapeHtml(last)} · every ${s.intervalMinutes} min</div>
      ${err}
      <div class="health-row-actions">
        <button class="action-btn" id="chooseFolderBtn">Choose folder</button>
        <button class="action-btn" id="syncNowBtn" ${s.destination ? '' : 'disabled'}>Sync now</button>
        <select id="offsiteInterval" style="margin-left:8px; background: var(--panel); color: var(--text); border: 1px solid var(--border); border-radius: 5px; padding: 3px 6px; font-size: 11.5px;">
          <option value="5" ${s.intervalMinutes === 5 ? 'selected' : ''}>every 5 min</option>
          <option value="15" ${s.intervalMinutes === 15 ? 'selected' : ''}>every 15 min</option>
          <option value="60" ${s.intervalMinutes === 60 ? 'selected' : ''}>every hour</option>
        </select>
      </div>
    </div>`;

  document.getElementById('chooseFolderBtn').addEventListener('click', async () => {
    const r = await window.watchAPI.chooseOffsiteFolder();
    if (!r.canceled) renderOffsite(r.settings);
  });

  document.getElementById('syncNowBtn').addEventListener('click', async (e) => {
    e.target.disabled = true;
    e.target.textContent = 'Syncing…';
    const r = await window.watchAPI.syncOffsiteNow();
    alert(r.ok ? `Synced ${r.copied} files to:\n${r.targetDir}` : `Sync failed: ${r.error}`);
    loadOffsite();
  });

  const toggle = document.getElementById('offsiteToggle');
  toggle.addEventListener('change', async () => {
    renderOffsite(await window.watchAPI.setOffsiteEnabled(toggle.checked));
  });

  document.getElementById('offsiteInterval').addEventListener('change', async (e) => {
    renderOffsite(await window.watchAPI.setOffsiteInterval(Number(e.target.value)));
  });
}

async function loadOffsite() {
  renderOffsite(await window.watchAPI.getOffsiteSettings());
}

// ---------- Exposure tab ----------
const exposureBody = document.getElementById('exposureBody');
const scanExposureBtn = document.getElementById('scanExposureBtn');
let exposureLoaded = false;

function findingHtml(f) {
  return `<div class="alert ${f.severity}">
    <div class="alert-body">
      <div class="alert-title">${escapeHtml(f.title)}</div>
      <div class="alert-detail">${escapeHtml(f.detail)}</div>
    </div>
  </div>`;
}

function renderExposure(d) {
  const findings = d.findings.length
    ? d.findings.map(findingHtml).join('')
    : '<div class="feed-empty">No exposure issues found.</div>';

  const exposed = d.listening.filter((l) => l.exposed);
  const localOnly = d.listening.filter((l) => !l.exposed);

  const portRow = (l) =>
    `<tr>
      <td>${l.port}${l.service ? ` <span class="tag unsigned">${escapeHtml(l.service)}</span>` : ''}</td>
      <td>${escapeHtml(l.address)}</td>
      <td>${escapeHtml(l.name)}</td>
      <td>${l.exposed ? '<span class="tag no">reachable</span>' : '<span class="tag yes">local only</span>'}</td>
    </tr>`;

  const adapterRows = d.adapters
    .map(
      (a) =>
        `<tr><td>${escapeHtml(a.adapter)}</td><td>${escapeHtml(a.ip)}</td><td>${
          a.kind === 'public'
            ? '<span class="tag no">public — no NAT</span>'
            : `<span class="tag yes">${escapeHtml(a.kind)}</span>`
        }</td></tr>`
    )
    .join('');

  const fwRows = d.firewall
    .map(
      (f) =>
        `<tr><td>${escapeHtml(f.profile)}</td><td>${
          f.enabled ? '<span class="tag yes">on</span>' : '<span class="tag no">OFF</span>'
        }</td><td>${escapeHtml(f.defaultInbound)}</td></tr>`
    )
    .join('');

  const hostsRows = d.hosts.length
    ? d.hosts
        .map((h) => `<div class="health-row">${escapeHtml(h.line)}</div>`)
        .join('')
    : '<div class="feed-empty">No custom entries — hosts file is clean.</div>';

  const tunnelRows = d.tunnels.length
    ? d.tunnels
        .map(
          (t) =>
            `<div class="health-row"${t.active && !t.recognized ? '' : ' style="border-left-color: var(--teal);"'}>
              ${escapeHtml(t.name)} — ${escapeHtml(t.description)}<br>
              <span style="color: var(--muted);">${escapeHtml(t.status)}${t.recognized ? ' · recognized VPN software' : ' · not matched to known VPN software'}</span>
            </div>`
        )
        .join('')
    : '<div class="feed-empty">No tunnel or VPN adapters present.</div>';

  const dnsRows = d.dns
    .map(
      (x) =>
        `<div class="health-row" style="border-left-color: var(--teal);">${escapeHtml(x.adapter)}: ${escapeHtml(x.servers.join(', '))}</div>`
    )
    .join('') || '<div class="feed-empty">No DNS servers reported.</div>';

  const shareRows = d.shares
    .map(
      (s) =>
        `<tr><td>${escapeHtml(s.name)}</td><td>${escapeHtml(s.path || '')}</td><td>${
          s.administrative
            ? '<span class="tag yes">built-in</span>'
            : '<span class="tag unsigned">shared</span>'
        }</td></tr>`
    )
    .join('');

  exposureBody.innerHTML = `
    <div class="debloat-section-title">Findings</div>
    ${findings}

    <div class="health-row-actions" style="margin: 14px 0 20px;">
      <button class="action-btn" id="openRdpBtn">Remote Desktop settings</button>
      <button class="action-btn" id="openFwBtn">Firewall settings</button>
      <button class="action-btn" id="openProxyBtn">Proxy settings</button>
    </div>

    <div class="debloat-section-title">Listening ports — reachable from the network (${exposed.length})</div>
    <table class="data-table"><thead><tr><th>Port</th><th>Bound to</th><th>Process</th><th>Scope</th></tr></thead>
    <tbody>${exposed.map(portRow).join('') || '<tr><td colspan="4" style="font-family:var(--sans);color:var(--muted);">Nothing reachable from outside this machine.</td></tr>'}</tbody></table>

    <div class="debloat-section-title">Listening ports — localhost only (${localOnly.length})</div>
    <div class="toggle-row-desc" style="margin-bottom:8px;">These cannot be reached from another machine. Listed for completeness.</div>
    <table class="data-table"><thead><tr><th>Port</th><th>Bound to</th><th>Process</th><th>Scope</th></tr></thead>
    <tbody>${localOnly.map(portRow).join('')}</tbody></table>

    <div class="debloat-section-title">Network adapters</div>
    <table class="data-table"><thead><tr><th>Adapter</th><th>IP</th><th>Type</th></tr></thead><tbody>${adapterRows}</tbody></table>

    <div class="debloat-section-title">Firewall profiles</div>
    <table class="data-table"><thead><tr><th>Profile</th><th>State</th><th>Default inbound</th></tr></thead><tbody>${fwRows}</tbody></table>

    <div class="debloat-section-title">Remote Desktop</div>
    <div class="health-row"${d.rdp.enabled ? '' : ' style="border-left-color: var(--teal);"'}>
      ${d.rdp.enabled ? `Enabled on port ${d.rdp.port} · Network Level Authentication: ${d.rdp.nlaRequired ? 'required' : 'NOT required'}` : 'Disabled — nothing can connect in over RDP.'}
    </div>

    <div class="debloat-section-title">DNS servers</div>
    ${dnsRows}

    <div class="debloat-section-title">Proxy</div>
    <div class="health-row"${d.proxy.enabled || d.proxy.autoConfigUrl ? '' : ' style="border-left-color: var(--teal);"'}>
      ${d.proxy.enabled && d.proxy.server ? `System proxy: ${escapeHtml(d.proxy.server)}` : 'No system proxy configured.'}
      ${d.proxy.autoConfigUrl ? `<br>Auto-config URL: ${escapeHtml(d.proxy.autoConfigUrl)}` : ''}
      ${d.proxy.winhttp ? `<br><span style="color: var(--muted);">WinHTTP: ${escapeHtml(d.proxy.winhttp.replace(/\s+/g, ' ').slice(0, 200))}</span>` : ''}
    </div>

    <div class="debloat-section-title">Hosts file</div>
    ${hostsRows}

    <div class="debloat-section-title">Tunnel / VPN adapters</div>
    ${tunnelRows}

    <div class="debloat-section-title">Network shares</div>
    <table class="data-table"><thead><tr><th>Share</th><th>Path</th><th>Type</th></tr></thead><tbody>${shareRows}</tbody></table>
  `;

  document.getElementById('openRdpBtn').addEventListener('click', () => window.watchAPI.openRdpSettings());
  document.getElementById('openFwBtn').addEventListener('click', () => window.watchAPI.openFirewallSettings());
  document.getElementById('openProxyBtn').addEventListener('click', () => window.watchAPI.openProxySettings());
}

async function runExposureScan() {
  scanExposureBtn.disabled = true;
  scanExposureBtn.textContent = 'Scanning…';
  exposureBody.innerHTML = '<div class="feed-empty">Checking ports, adapters, firewall, DNS, proxy, tunnels, and shares…</div>';
  try {
    const d = await window.watchAPI.scanExposure();
    exposureLoaded = true;
    renderExposure(d);
  } catch (err) {
    exposureBody.innerHTML = `<div class="feed-empty">Scan failed: ${escapeHtml(err.message)}</div>`;
  } finally {
    scanExposureBtn.disabled = false;
    scanExposureBtn.textContent = 'Scan now';
  }
}

function loadExposureIfEmpty() {
  if (!exposureLoaded) runExposureScan();
}

scanExposureBtn.addEventListener('click', runExposureScan);

// ---------- Autostart ----------
const autostartRow = document.getElementById('autostartRow');

async function loadAutostart() {
  const enabled = await window.watchAPI.getAutostart();
  autostartRow.innerHTML = `
    <div class="toggle-row">
      <div class="toggle-row-text">
        <div class="toggle-row-label">Start Watchtower at logon (as Administrator)</div>
        <div class="toggle-row-desc">Registers a scheduled task so monitoring begins at boot with full privileges. Without this, anything that happens before you open the app manually goes unlogged.</div>
        <div class="toggle-row-note" style="display:none;"></div>
      </div>
      <label class="switch">
        <input type="checkbox" id="autostartToggle" ${enabled ? 'checked' : ''} />
        <span class="switch-track"></span>
      </label>
    </div>`;

  const input = document.getElementById('autostartToggle');
  const noteEl = autostartRow.querySelector('.toggle-row-note');
  input.addEventListener('change', async () => {
    const wantOn = input.checked;
    input.disabled = true;
    noteEl.style.display = 'none';
    const result = await window.watchAPI.setAutostart(wantOn);
    input.disabled = false;
    if (!result.ok) {
      input.checked = !wantOn;
      renderToggleNote(noteEl, { text: result.error, isError: true });
    } else if (result.note) {
      renderToggleNote(noteEl, { text: result.note, isError: false });
    }
  });
}

// ---------- Remote-tool watchlist ----------
const watchlistList = document.getElementById('watchlistList');
const newWatchInput = document.getElementById('newWatchInput');
const addWatchBtn = document.getElementById('addWatchBtn');

function renderWatchlist(info) {
  const customRows = info.custom.map(
    (n) =>
      `<li><span>${escapeHtml(n)} <span class="tag yes">custom</span></span><button data-remove-watch="${escapeHtml(n)}">Remove</button></li>`
  );
  const defaultRows = info.defaults.map((d) =>
    d.disabled
      ? `<li style="opacity:0.5;"><span>${escapeHtml(d.name)} <span class="tag no">off</span></span><button data-restore-watch="${escapeHtml(d.name)}">Restore</button></li>`
      : `<li><span>${escapeHtml(d.name)}</span><button data-remove-watch="${escapeHtml(d.name)}">Disable</button></li>`
  );
  watchlistList.innerHTML = [...customRows, ...defaultRows].join('');

  watchlistList.querySelectorAll('button[data-remove-watch]').forEach((btn) => {
    btn.addEventListener('click', async () => {
      renderWatchlist(await window.watchAPI.removeWatchlistEntry(btn.dataset.removeWatch));
    });
  });
  watchlistList.querySelectorAll('button[data-restore-watch]').forEach((btn) => {
    btn.addEventListener('click', async () => {
      renderWatchlist(await window.watchAPI.restoreWatchlistEntry(btn.dataset.restoreWatch));
    });
  });
}

async function loadWatchlist() {
  renderWatchlist(await window.watchAPI.getWatchlist());
}

addWatchBtn.addEventListener('click', async () => {
  const name = newWatchInput.value.trim();
  if (!name) return;
  renderWatchlist(await window.watchAPI.addWatchlistEntry(name));
  newWatchInput.value = '';
});
newWatchInput.addEventListener('keydown', (e) => {
  if (e.key === 'Enter') addWatchBtn.click();
});

addUserBtn.addEventListener('click', async () => {
  const name = newUserInput.value.trim();
  if (!name) return;
  const updated = await window.watchAPI.addKnownUser(name);
  newUserInput.value = '';
  renderKnownUsers(updated);
});
newUserInput.addEventListener('keydown', (e) => {
  if (e.key === 'Enter') addUserBtn.click();
});

// ---------- Debloat tab ----------
const debloatBody = document.getElementById('debloatBody');
let debloatCatalog = null;

function toggleRowHtml(kind, id, label, description, isOn) {
  return `<div class="toggle-row" data-kind="${kind}" data-id="${id}">
    <div class="toggle-row-text">
      <div class="toggle-row-label">${escapeHtml(label)}</div>
      <div class="toggle-row-desc">${escapeHtml(description || '')}</div>
      <div class="toggle-row-note" style="display:none;"></div>
    </div>
    <label class="switch">
      <input type="checkbox" ${isOn ? 'checked' : ''} ${isOn === null ? 'disabled' : ''} />
      <span class="switch-track"></span>
    </label>
  </div>`;
}

function renderToggleNote(noteEl, { text, isError, storeSearchTerm }) {
  noteEl.innerHTML = '';
  noteEl.classList.toggle('error', !!isError);
  const span = document.createElement('span');
  span.textContent = text;
  noteEl.appendChild(span);
  if (storeSearchTerm) {
    const btn = document.createElement('button');
    btn.className = 'action-btn';
    btn.style.marginLeft = '8px';
    btn.textContent = `Open "${storeSearchTerm}" in Microsoft Store`;
    btn.addEventListener('click', () => window.watchAPI.openStoreSearch(storeSearchTerm));
    noteEl.appendChild(btn);
  }
  noteEl.style.display = 'block';
}

async function loadDebloat() {
  if (!debloatCatalog) {
    debloatCatalog = await window.watchAPI.getDebloatCatalog();
  }
  debloatBody.innerHTML = '<div class="feed-empty">Checking current status…</div>';

  const [featureStates, appStates] = await Promise.all([
    window.watchAPI.getDebloatFeatureStates(),
    window.watchAPI.getDebloatAppStates(),
  ]);

  const featureRows = debloatCatalog.features
    .map((f) => {
      const state = featureStates[f.id];
      const isOn = state === 'on' ? true : state === 'off' ? false : null;
      return toggleRowHtml('feature', f.id, f.label, f.description, isOn);
    })
    .join('');

  const appRows = debloatCatalog.apps
    .map((a) => {
      const state = appStates[a.id];
      const isOn = state === 'installed' ? true : state === 'removed' ? false : null;
      return toggleRowHtml('app', a.id, a.label, 'Toggle off to uninstall; toggle back on to try restoring it.', isOn);
    })
    .join('');

  debloatBody.innerHTML = `
    <div class="debloat-section-title">Privacy &amp; telemetry (fully reversible)</div>
    ${featureRows}
    <div class="debloat-section-title">Bundled apps</div>
    ${appRows}
  `;

  debloatBody.querySelectorAll('.toggle-row').forEach((row) => {
    const input = row.querySelector('input[type="checkbox"]');
    const noteEl = row.querySelector('.toggle-row-note');
    input.addEventListener('change', async () => {
      const wantOn = input.checked;
      input.disabled = true;
      noteEl.style.display = 'none';
      const kind = row.dataset.kind;
      const id = row.dataset.id;
      const result =
        kind === 'feature'
          ? await window.watchAPI.setDebloatFeature(id, wantOn)
          : await window.watchAPI.setDebloatApp(id, wantOn);
      input.disabled = false;
      if (!result.ok) {
        input.checked = !wantOn; // revert the switch visually
        renderToggleNote(noteEl, { text: result.error, isError: true, storeSearchTerm: result.storeSearchTerm });
      } else if (result.note) {
        renderToggleNote(noteEl, { text: result.note, isError: false, storeSearchTerm: result.storeSearchTerm });
      }
    });
  });
}

