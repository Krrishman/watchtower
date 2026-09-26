'use strict';

const api = window.watchAPI;

// ---------- tiny DOM helper: all dynamic text goes through textContent ----------
function h(tag, props = {}, ...children) {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(props || {})) {
    if (v == null || v === false) continue;
    if (k === 'class') el.className = v;
    else if (k === 'text') el.textContent = v;
    else if (k.startsWith('on')) el.addEventListener(k.slice(2), v);
    else if (k === 'dataset') Object.assign(el.dataset, v);
    else if (k === 'checked' || k === 'disabled' || k === 'value') el[k] = v;
    else el.setAttribute(k, v === true ? '' : v);
  }
  for (const c of children.flat()) {
    if (c == null || c === false) continue;
    el.append(c instanceof Node ? c : document.createTextNode(String(c)));
  }
  return el;
}

const $ = (id) => document.getElementById(id);
const clear = (el) => { el.replaceChildren(); return el; };
// Kept by reference: it is detached and re-attached whenever the feed is rebuilt.
const feedEmpty = $('feedEmpty');

const state = {
  connected: false,
  isAdmin: false,
  user: '',
  setupCompleted: true,
  settings: null,
  alerts: new Map(),
};

async function call(method, params) {
  const r = await api.rpc(method, params);
  if (!r.ok) {
    const err = new Error(r.error);
    err.code = r.code;
    throw err;
  }
  return r.result;
}

// ---------- modal / toast ----------
function modal({ title, body, actions }) {
  return new Promise((resolve) => {
    $('modalTitle').textContent = title;
    const bodyEl = clear($('modalBody'));
    (Array.isArray(body) ? body : [body]).forEach((b) => bodyEl.append(typeof b === 'string' ? h('p', { text: b }) : b));
    const actionsEl = clear($('modalActions'));
    const close = (value) => {
      $('modal').classList.add('hidden');
      document.removeEventListener('keydown', onKey);
      resolve(value);
    };
    const onKey = (e) => { if (e.key === 'Escape') close(null); };
    document.addEventListener('keydown', onKey);
    actions.forEach((a) => actionsEl.append(h('button', { class: a.primary ? (a.danger ? 'primary-btn danger' : 'primary-btn') : 'action-btn', text: a.label, onclick: () => close(a.value) })));
    $('modal').classList.remove('hidden');
    actionsEl.lastChild?.focus();
  });
}

const info = (title, message) => modal({ title, body: message, actions: [{ label: 'OK', value: true, primary: true }] });

let toastTimer = null;
function toast(message, kind = 'ok') {
  const t = $('toast');
  t.textContent = message;
  t.className = `toast ${kind}`;
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => t.classList.add('hidden'), 4500);
}

function explainError(err) {
  if (err.code === 'forbidden') return 'This needs an administrator account on this PC. You can look at everything, but only an administrator can change things.';
  if (err.code === 'offline') return 'The Watchtower service is not running, so this can\'t be done right now.';
  return err.message;
}

/**
 * Every system-changing action goes: ask the service's safety guard → explain in
 * plain English → confirm → act. The service enforces the guard again on its side.
 */
async function guarded({ guardMethod, guardParams, title, confirmLabel, actMethod, actParams, success }) {
  try {
    const decision = await call(guardMethod, guardParams);
    if (decision.verdict === 'Deny') {
      await info("Watchtower won't do this", decision.reason);
      return false;
    }
    const ok = await modal({
      title,
      body: decision.reason,
      actions: [{ label: 'Cancel', value: false }, { label: confirmLabel, value: true, primary: true, danger: true }],
    });
    if (!ok) return false;
    await call(actMethod, actParams);
    toast(success);
    return true;
  } catch (err) {
    await info("That didn't work", explainError(err));
    return false;
  }
}

const actions = {
  kill: (pid, name) => guarded({
    guardMethod: 'guard.kill', guardParams: { pid: Number(pid) },
    title: `End ${name || 'this program'}?`, confirmLabel: 'End program',
    actMethod: 'process.kill', actParams: { pid: Number(pid) }, success: `${name || 'Program'} was ended.`,
  }),
  block: (address) => guarded({
    guardMethod: 'guard.block', guardParams: { address },
    title: `Block ${address}?`, confirmLabel: 'Block',
    actMethod: 'network.block', actParams: { address }, success: `${address} is now blocked.`,
  }).then((ok) => { if (ok) loadBlocked(); return ok; }),
  disconnect: (sessionId, user) => guarded({
    guardMethod: 'guard.disconnect', guardParams: { sessionId: Number(sessionId) },
    title: `Sign out ${user || 'this session'}?`, confirmLabel: 'Sign out',
    actMethod: 'session.disconnect', actParams: { sessionId: Number(sessionId) }, success: 'The session was signed out.',
  }),
  removeStartup: (key, name) => guarded({
    guardMethod: 'guard.removeStartup', guardParams: { key },
    title: `Remove "${name}" from startup?`, confirmLabel: 'Remove from startup',
    actMethod: 'startup.remove', actParams: { key }, success: `"${name}" won't start automatically any more.`,
  }),
};

// ---------- connection / identity ----------
function renderBanner() {
  const b = $('banner');
  let text = null;
  let kind = 'warn';
  if (!state.connected) {
    text = 'The Watchtower service isn\'t running, so nothing is being monitored right now. It normally restarts by itself within a few seconds. If this message stays, restart the PC or reinstall Watchtower.';
    kind = 'bad';
  } else if (!state.isAdmin) {
    text = 'You\'re signed in with a standard account. You can see everything, but ending programs, blocking addresses and changing settings needs an administrator.';
  } else if (state.settings?.learning) {
    const until = new Date(state.settings.learningUntil);
    text = `Learning what's normal for this PC until ${until.toLocaleString()}. Routine "first time" events are quiet until then; anything serious still alerts right away.`;
    kind = 'info';
  }
  b.className = text ? `banner ${kind}` : 'banner hidden';
  b.textContent = text || '';

  $('statusDot').classList.toggle('on', state.connected);
  $('statusText').textContent = state.connected ? 'Monitoring' : 'Not monitoring';
}

async function onConnected() {
  state.connected = true;
  try {
    const hello = await call('hello');
    state.isAdmin = hello.isAdmin;
    state.user = hello.user;
    state.setupCompleted = hello.setupCompleted;
    state.settings = await call('settings.get');
    const snapshot = await call('state.get');
    applyState(snapshot);
    await loadRecentAlerts();
    $('railNote').textContent = `Version ${hello.version} · signed in as ${hello.user}${hello.isAdmin ? ' (administrator)' : ''}`;
    if (!hello.setupCompleted) openWizard();
  } catch (err) {
    console.error(err);
  }
  renderBanner();
}

api.onServiceStatus(({ connected }) => {
  if (connected) onConnected();
  else {
    state.connected = false;
    renderBanner();
  }
});

// ---------- rail ----------
function setRail(source, value, flagged) {
  const el = $(`count-${source}`);
  if (el) el.textContent = value;
  document.querySelector(`.rail-item[data-source="${source}"]`)?.classList.toggle('flagged', !!flagged);
}

function renderSensors(sensors) {
  clear($('sensorList')).append(...sensors.map((s) => h('div', {
    class: `rail-item small${s.mode === 'live' || s.mode === 'none' ? '' : ' flagged'}`,
    title: s.detail || '',
  }, h('span', { class: 'rail-label', text: s.name }), h('span', { class: 'rail-value', text: s.mode }))));
}

// ---------- alerts ----------
const ACTION_LABELS = {
  kill: 'End program',
  block: 'Block address',
  disconnect: 'Sign out session',
  removeStartup: 'Remove from startup',
  openWindowsSecurity: 'Open Windows Security',
  openRdpSettings: 'Remote Desktop settings',
  verifyHistory: 'Check history',
};

function actionHandler(action, alert) {
  const s = alert.subject || {};
  switch (action) {
    case 'kill': return s.pid ? () => actions.kill(s.pid, s.processName) : null;
    case 'block': return (s.remoteAddress || s.clientAddress) ? () => actions.block(s.remoteAddress || s.clientAddress) : null;
    case 'disconnect': return s.sessionId ? () => actions.disconnect(s.sessionId, s.account) : null;
    case 'removeStartup': return s.startupKey ? () => actions.removeStartup(s.startupKey, s.startupName) : null;
    case 'openWindowsSecurity': return () => api.openExternal('windowsSecurity');
    case 'openRdpSettings': return () => api.openExternal('rdpSettings');
    case 'verifyHistory': return () => { selectTab('history'); runVerify(); };
    default: return null;
  }
}

function formatTime(iso) {
  const d = new Date(iso);
  const sameDay = d.toDateString() === new Date().toDateString();
  return sameDay ? d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }) : d.toLocaleDateString([], { month: 'short', day: 'numeric' }) + ' ' + d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
}

function alertCard(alert, { interactive = true } = {}) {
  const buttons = [];
  if (interactive) {
    for (const a of alert.actions || []) {
      const fn = actionHandler(a, alert);
      if (fn) buttons.push(h('button', { class: a === 'kill' || a === 'block' || a === 'disconnect' || a === 'removeStartup' ? 'action-btn danger' : 'action-btn', text: ACTION_LABELS[a] || a, onclick: fn }));
    }
    if (alert.trustOptions?.length) buttons.push(trustMenu(alert));
    buttons.push(h('button', { class: 'action-btn subtle', text: 'Dismiss', onclick: () => dismiss([alert.id]) }));
  }

  const details = h('div', { class: 'alert-more hidden' },
    alert.explanation ? h('div', {}, h('div', { class: 'more-label', text: 'What this means' }), h('p', { text: alert.explanation })) : null,
    alert.advice ? h('div', {}, h('div', { class: 'more-label', text: 'What to do' }), h('p', { text: alert.advice })) : null);

  const toggle = h('button', { class: 'link-btn', text: 'What does this mean?', 'aria-expanded': 'false' });
  toggle.addEventListener('click', () => {
    const open = details.classList.toggle('hidden') === false;
    toggle.textContent = open ? 'Hide details' : 'What does this mean?';
    toggle.setAttribute('aria-expanded', String(open));
  });

  const note = alert.suppressedBy
    ? h('span', { class: 'tag quiet', text: alert.suppressedBy.startsWith('trust:') ? 'trusted, logged quietly' : 'quiet' })
    : null;

  return h('div', { class: `alert ${alert.severity}${alert.suppressedBy ? ' suppressed' : ''}`, dataset: { id: alert.id } },
    h('div', { class: 'alert-time', text: formatTime(alert.time) }),
    h('div', { class: 'alert-body' },
      h('div', { class: 'alert-title' }, h('span', { class: `sev ${alert.severity}`, text: alert.severity === 'critical' ? 'Urgent' : alert.severity === 'warn' ? 'Check' : 'FYI' }), ' ', alert.title, note ? ' ' : null, note),
      h('div', { class: 'alert-detail', text: alert.detail }),
      (alert.explanation || alert.advice) ? toggle : null,
      details,
      buttons.length ? h('div', { class: 'alert-actions' }, buttons) : null));
}

function trustMenu(alert) {
  const wrap = h('span', { class: 'menu-wrap' });
  const list = h('div', { class: 'menu hidden', role: 'menu' });
  for (const opt of alert.trustOptions) {
    list.append(h('button', {
      role: 'menuitem',
      text: opt.label,
      onclick: async () => {
        list.classList.add('hidden');
        const ok = await modal({
          title: opt.label + '?',
          body: [
            'Watchtower will stop alerting you about this. It will still be written to the history log, marked as trusted.',
            'You can undo this at any time in Settings > Trusted.',
          ],
          actions: [{ label: 'Cancel', value: false }, { label: 'Trust', value: true, primary: true }],
        });
        if (!ok) return;
        try {
          await call('trust.add', { type: opt.type, value: opt.value, processPath: opt.processPath, label: opt.label.replace(/^Trust /, '') });
          await dismiss([alert.id], true);
          toast('Trusted. You won\'t be alerted about this again.');
        } catch (err) {
          info("Couldn't add trust", explainError(err));
        }
      },
    }));
  }
  const btn = h('button', { class: 'action-btn', text: 'Trust…', 'aria-haspopup': 'menu', onclick: (e) => { e.stopPropagation(); document.querySelectorAll('.menu').forEach((m) => m !== list && m.classList.add('hidden')); list.classList.toggle('hidden'); } });
  wrap.append(btn, list);
  return wrap;
}
document.addEventListener('click', () => document.querySelectorAll('.menu').forEach((m) => m.classList.add('hidden')));

function addAlert(alert, { prepend = true } = {}) {
  // Audit entries (your own actions) belong in History, not the alerts feed.
  if (alert.suppressedBy || alert.source === 'audit' || state.alerts.has(alert.id)) return;
  state.alerts.set(alert.id, alert);
  feedEmpty.style.display = 'none';
  const card = alertCard(alert);
  if (prepend) $('feed').prepend(card);
  else $('feed').append(card);
}

async function loadRecentAlerts() {
  const recent = await call('alerts.recent', { limit: 200 });
  state.alerts.clear();
  clear($('feed')).append(feedEmpty);
  feedEmpty.style.display = recent.length ? 'none' : '';
  recent.forEach((a) => addAlert(a, { prepend: false }));
}

async function dismiss(ids, quiet = false) {
  try {
    await call('alerts.dismiss', { ids });
    ids.forEach((id) => {
      state.alerts.delete(id);
      document.querySelector(`#feed .alert[data-id="${CSS.escape(id)}"]`)?.remove();
    });
    if (!state.alerts.size) feedEmpty.style.display = '';
  } catch (err) {
    if (!quiet) info("Couldn't dismiss", explainError(err));
  }
}

$('dismissAllBtn').addEventListener('click', async () => {
  if (!state.alerts.size) return;
  const ok = await modal({ title: 'Dismiss all alerts?', body: 'They\'ll stay in the History tab.', actions: [{ label: 'Cancel', value: false }, { label: 'Dismiss all', value: true, primary: true }] });
  if (ok) dismiss([...state.alerts.keys()]);
});

api.onAlert((alert) => {
  addAlert(alert);
  if (alert.source === 'audit' && !$('panel-history').classList.contains('hidden')) loadHistory();
});

// ---------- snapshots ----------
function applyState(s) {
  onSnapshot({ key: 'sessions', rows: s.sessions });
  onSnapshot({ key: 'network', rows: s.network });
  onSnapshot({ key: 'processTable', rows: s.processTable });
  onSnapshot({ key: 'processes', rows: s.processes });
  onSnapshot({ key: 'cameraMic', rows: s.cameraMic });
  onSnapshot({ key: 'sensors', rows: s.sensors });
}

function onSnapshot({ key, rows }) {
  rows = rows || [];
  if (key === 'sessions') {
    const remote = rows.filter((r) => r.remote).length;
    setRail('sessions', remote, remote > 0);
    renderSessions(rows);
  } else if (key === 'processes') {
    setRail('processes', rows.length, rows.length > 0);
  } else if (key === 'network') {
    setRail('network', rows.length, false);
    renderNetwork(rows);
  } else if (key === 'cameraMic') {
    const active = rows.filter((r) => r.active).length;
    setRail('cameraMic', active, active > 0);
  } else if (key === 'processTable') {
    renderProcesses(rows);
  } else if (key === 'sensors') {
    renderSensors(rows);
  }
}
api.onSnapshot(onSnapshot);

function emptyRow(cols, text) {
  return h('tr', {}, h('td', { colspan: String(cols), class: 'empty-cell', text }));
}

function renderSessions(rows) {
  clear($('sessionsTableBody')).append(...(rows.length ? rows.map((r) => h('tr', {},
    h('td', { text: r.username }),
    h('td', { text: `${r.sessionName || '—'} (${r.state})` }),
    h('td', { text: r.remote ? (r.clientName || r.clientAddress || 'unknown') : 'this PC' }),
    h('td', {}, r.remote ? h('span', { class: 'tag unsigned', text: 'Remote Desktop' }) : h('span', { class: 'tag yes', text: 'local' })),
    h('td', {}, h('button', { class: 'action-btn danger', text: 'Sign out', disabled: !state.isAdmin, title: state.isAdmin ? null : 'Needs an administrator account', onclick: () => actions.disconnect(r.id, r.username) })),
  )) : [emptyRow(5, 'No one is signed in.')]));
}

function renderProcesses(rows) {
  clear($('processTableBody')).append(...rows.map((r) => {
    const sig = r.signed ? h('span', { class: 'tag yes', text: r.signer || 'verified' }) : h('span', { class: 'tag unsigned', text: r.signatureStatus === 'NotSigned' ? 'not signed' : r.signatureStatus });
    const kill = r.killable
      ? h('button', { class: 'action-btn danger', text: 'End', disabled: !state.isAdmin, title: state.isAdmin ? null : 'Needs an administrator account', onclick: () => actions.kill(r.pid, r.name) })
      : h('span', { class: 'tag protected', text: 'Protected', title: r.protection || '' });
    return h('tr', {},
      h('td', { text: r.name }),
      h('td', { text: String(r.pid) }),
      h('td', {}, sig),
      h('td', {}, r.networked ? h('span', { class: 'tag yes', text: 'yes' }) : h('span', { class: 'tag no-muted', text: 'no' })),
      h('td', { text: r.path || '', title: r.path || '' }),
      h('td', {}, kill));
  }));
}

function renderNetwork(rows) {
  clear($('networkTableBody')).append(...(rows.length ? rows.map((r) => h('tr', {},
    h('td', { text: r.process, title: r.path || '' }),
    h('td', { text: r.remoteAddress }),
    h('td', { text: String(r.remotePort) }),
    h('td', {}, r.inbound ? h('span', { class: 'tag unsigned', text: 'incoming' }) : h('span', { class: 'tag yes', text: 'outgoing' })),
    h('td', {}, h('button', { class: 'action-btn danger', text: 'Block', disabled: !state.isAdmin, onclick: () => actions.block(r.remoteAddress) })),
  )) : [emptyRow(5, 'No connections to other computers right now.')]));
}

async function loadBlocked() {
  const addresses = await call('network.blocked').catch(() => []);
  clear($('blockedList')).append(...(addresses.length ? addresses.map((a) => h('li', {},
    h('span', { text: a }),
    h('button', {
      text: 'Unblock',
      disabled: !state.isAdmin,
      onclick: async () => {
        try {
          await call('network.unblock', { address: a });
          toast(`${a} is no longer blocked.`);
          loadBlocked();
        } catch (err) {
          info("Couldn't unblock", explainError(err));
        }
      },
    }))) : [h('li', { class: 'muted', text: 'Nothing blocked.' })]));
}

// ---------- history ----------
async function loadHistory() {
  const source = $('historyFilter').value || undefined;
  const entries = await call('history.get', { limit: 400, source }).catch(() => []);
  clear($('historyList')).append(...(entries.length ? entries.map((e) => alertCard(e, { interactive: false })) : [h('div', { class: 'feed-empty', text: 'Nothing recorded yet for this filter.' })]));
}
$('historyFilter').addEventListener('change', loadHistory);

async function runVerify() {
  const btn = $('verifyBtn');
  btn.disabled = true;
  btn.textContent = 'Checking…';
  try {
    const r = await call('history.verify');
    $('integrityBar').className = 'integrity-bar ' + (r.ok ? 'ok' : r.unverifiable ? 'warn' : 'bad');
    $('integrityBar').textContent = (r.ok ? '✓ ' : '⚠ ') + r.message;
  } catch (err) {
    $('integrityBar').className = 'integrity-bar bad';
    $('integrityBar').textContent = explainError(err);
  } finally {
    btn.disabled = false;
    btn.textContent = 'Check for tampering';
  }
}
$('verifyBtn').addEventListener('click', runVerify);

async function exportHistory(format) {
  const r = await api.exportHistory(format, $('historyFilter').value || null);
  if (r.canceled) return;
  if (r.ok) toast(`Exported ${r.count} entries.`);
  else info('Export failed', r.error);
}
$('exportCsvBtn').addEventListener('click', () => exportHistory('csv'));
$('exportJsonBtn').addEventListener('click', () => exportHistory('json'));

// ---------- exposure ----------
function section(title, ...content) {
  return [h('div', { class: 'section-title', text: title }), ...content];
}

function table(headers, rows, empty) {
  return h('table', { class: 'data-table' },
    h('thead', {}, h('tr', {}, headers.map((x) => h('th', { text: x })))),
    h('tbody', {}, rows.length ? rows : [emptyRow(headers.length, empty)]));
}

function finding(f) {
  return h('div', { class: `alert ${f.severity}` }, h('div', { class: 'alert-body' }, h('div', { class: 'alert-title', text: f.title }), h('div', { class: 'alert-detail', text: f.detail })));
}

function row(text, ok) {
  return h('div', { class: `health-row${ok ? ' ok' : ''}`, text });
}

function renderExposure(d) {
  const exposed = d.listening.filter((l) => l.exposed);
  const local = d.listening.filter((l) => !l.exposed);
  const portRow = (l) => h('tr', {},
    h('td', {}, String(l.port), l.service ? ' ' : null, l.service ? h('span', { class: 'tag unsigned', text: l.service }) : null),
    h('td', { text: l.address }), h('td', { text: l.name, title: l.path || '' }),
    h('td', {}, l.exposed ? h('span', { class: 'tag no', text: 'reachable' }) : h('span', { class: 'tag yes', text: 'this PC only' })));

  clear($('exposureBody')).append(
    ...section('Findings', ...(d.findings.length ? d.findings.map(finding) : [h('div', { class: 'feed-empty', text: 'Nothing exposed that needs attention.' })])),
    h('div', { class: 'button-row' },
      h('button', { class: 'action-btn', text: 'Remote Desktop settings', onclick: () => api.openExternal('rdpSettings') }),
      h('button', { class: 'action-btn', text: 'Firewall settings', onclick: () => api.openExternal('firewallSettings') }),
      h('button', { class: 'action-btn', text: 'Proxy settings', onclick: () => api.openExternal('proxySettings') })),
    ...section(`Open ports reachable from the network (${exposed.length})`, table(['Port', 'Listening on', 'Program', 'Reach'], exposed.map(portRow), 'Nothing on this PC accepts connections from other computers.')),
    ...section(`Open ports for this PC only (${local.length})`, h('p', { class: 'muted small', text: 'Other computers can\'t reach these. Listed for completeness.' }), table(['Port', 'Listening on', 'Program', 'Reach'], local.map(portRow), 'None.')),
    ...section('Network adapters', table(['Adapter', 'Address', 'Type'], d.adapters.map((a) => h('tr', {}, h('td', { text: a.adapter }), h('td', { text: a.ip }), h('td', {}, a.kind === 'public' ? h('span', { class: 'tag no', text: 'public, no router' }) : h('span', { class: 'tag yes', text: a.kind })))), 'None.')),
    ...section('Windows Firewall', table(['Network type', 'Firewall', 'Incoming by default'], d.firewall.map((f) => h('tr', {}, h('td', { text: f.profile }), h('td', {}, f.enabled ? h('span', { class: 'tag yes', text: 'on' }) : h('span', { class: 'tag no', text: 'OFF' })), h('td', { text: f.defaultInbound }))), 'Unknown.')),
    ...section('Remote Desktop', row(d.rdp.enabled ? `On, port ${d.rdp.port}. Network Level Authentication ${d.rdp.nlaRequired ? 'required (safer)' : 'NOT required'}.` : 'Off. Nothing can connect in over Remote Desktop.', !d.rdp.enabled)),
    ...section('DNS servers', ...(d.dns.length ? d.dns.map((x) => row(`${x.adapter}: ${x.servers.join(', ')}`, true)) : [h('div', { class: 'feed-empty', text: 'None reported.' })])),
    ...section('Proxy', row([
      d.proxy.enabled && d.proxy.server ? `Web traffic goes through ${d.proxy.server}.` : 'No proxy for web browsing.',
      d.proxy.autoConfigUrl ? ` Settings loaded from ${d.proxy.autoConfigUrl}.` : '',
      d.proxy.winHttp ? ` System services: ${d.proxy.winHttp}` : '',
    ].join(''), !(d.proxy.enabled || d.proxy.autoConfigUrl))),
    ...section('Hosts file', ...(d.hosts.length ? d.hosts.map((x) => row(x.line, false)) : [row('No custom entries.', true)])),
    ...section('Tunnels and VPNs', ...(d.tunnels.length ? d.tunnels.map((t) => row(`${t.name} (${t.description}): ${t.status}${t.recognized ? ', known VPN software' : ', not recognized'}`, !t.active || t.recognized)) : [row('None.', true)])),
    ...section('Shared folders', table(['Share', 'Folder', 'Type'], d.shares.map((s) => h('tr', {}, h('td', { text: s.name }), h('td', { text: s.path || '' }), h('td', {}, s.administrative ? h('span', { class: 'tag yes', text: 'built into Windows' }) : h('span', { class: 'tag unsigned', text: 'shared by someone' })))), 'Nothing shared.')),
  );
}

let exposureLoaded = false;
async function runExposure() {
  const btn = $('scanExposureBtn');
  btn.disabled = true;
  btn.textContent = 'Scanning…';
  clear($('exposureBody')).append(h('div', { class: 'feed-empty', text: 'Checking ports, adapters, firewall, DNS, proxy, tunnels and shares…' }));
  try {
    renderExposure(await call('exposure.scan'));
    exposureLoaded = true;
  } catch (err) {
    clear($('exposureBody')).append(h('div', { class: 'feed-empty', text: `Scan failed: ${explainError(err)}` }));
  } finally {
    btn.disabled = false;
    btn.textContent = 'Scan now';
  }
}
$('scanExposureBtn').addEventListener('click', runExposure);

// ---------- health ----------
async function runHealth() {
  const btn = $('runHealthBtn');
  btn.disabled = true;
  btn.textContent = 'Checking…';
  clear($('healthResults')).append(h('div', { class: 'feed-empty', text: 'Checking Defender, startup items and open ports…' }));
  try {
    const r = await call('health.run');
    const d = r.defender;
    clear($('healthResults')).append(
      ...section('Microsoft Defender', row(d.available
        ? `Antivirus ${d.antivirusEnabled ? 'on' : 'OFF'} · Real-time protection ${d.realTimeProtectionEnabled ? 'on' : 'OFF'} · Definitions updated ${d.signaturesUpdated ? new Date(d.signaturesUpdated).toLocaleString() : 'unknown'} · Last quick scan ${d.lastQuickScan ? new Date(d.lastQuickScan).toLocaleString() : 'never'}`
        : d.message, d.available && d.realTimeProtectionEnabled)),
      ...(r.threats.length ? section('Threats Defender found',
        ...r.threats.map((t) => h('div', { class: 'health-row critical', text: `${t.name}${t.process ? ` (${t.process})` : ''}${t.detectedAt ? ` · found ${new Date(t.detectedAt).toLocaleString()}` : ''}` })),
        h('button', { class: 'primary-btn danger', text: 'Open Windows Security to remove', onclick: () => api.openExternal('windowsSecurity') })) : []),
      ...section('Startup items worth a look',
        ...(r.startupFindings.length ? r.startupFindings.map((f) => h('div', { class: 'health-row' },
          h('div', { class: 'strong', text: f.name }),
          h('div', { class: 'muted', text: `${f.location} · ${f.signatureText}${f.suspectDir ? ' · runs from a Downloads or Temp folder' : ''}` }),
          h('div', { class: 'mono small', text: f.command }),
          h('div', { class: 'button-row' }, f.removable
            ? h('button', { class: 'action-btn danger', text: 'Remove from startup', disabled: !state.isAdmin, onclick: () => actions.removeStartup(f.key, f.name).then((ok) => ok && runHealth()) })
            : h('span', { class: 'tag protected', text: 'Protected', title: f.protection || '' })))) : [row('Everything that starts automatically is signed and in a normal location.', true)])),
      ...section('Unverified programs accepting connections',
        ...(r.listeningFindings.length ? r.listeningFindings.map((f) => h('div', { class: 'health-row' },
          h('div', { class: 'strong', text: `${f.name} on port ${f.port}` }),
          h('div', { class: 'muted', text: `${f.signatureText} · ${f.path || 'location unknown'}` }),
          h('div', { class: 'button-row' }, h('button', { class: 'action-btn danger', text: 'End program', disabled: !state.isAdmin, onclick: () => actions.kill(f.pid, f.name) })))) : [row('No unsigned programs are accepting connections.', true)])),
    );
  } catch (err) {
    clear($('healthResults')).append(h('div', { class: 'feed-empty', text: `Health check failed: ${explainError(err)}` }));
  } finally {
    btn.disabled = false;
    btn.textContent = 'Run Health Check';
  }
}
$('runHealthBtn').addEventListener('click', runHealth);
$('quickScanBtn').addEventListener('click', async () => {
  try {
    const r = await call('defender.scan');
    if (r.started) toast('Quick scan started. It runs in the background and takes a few minutes.');
    else info("Couldn't start a scan", r.error);
  } catch (err) {
    info("Couldn't start a scan", explainError(err));
  }
});

// ---------- privacy (debloat) ----------
function switchRow({ label, description, on, disabled, onChange }) {
  const note = h('div', { class: 'toggle-row-note hidden' });
  const input = h('input', { type: 'checkbox', checked: on === true, disabled: on === null || disabled, 'aria-label': label });
  input.addEventListener('change', async () => {
    const want = input.checked;
    input.disabled = true;
    note.classList.add('hidden');
    const result = await onChange(want);
    input.disabled = false;
    if (!result.ok) input.checked = !want;
    if (result.message || result.error) {
      note.replaceChildren(document.createTextNode(result.error || result.message));
      note.classList.toggle('error', !result.ok);
      if (result.storeSearchTerm) note.append(' ', h('button', { class: 'action-btn', text: `Open "${result.storeSearchTerm}" in the Microsoft Store`, onclick: () => api.openStoreSearch(result.storeSearchTerm) }));
      note.classList.remove('hidden');
    }
  });
  return h('div', { class: 'toggle-row' },
    h('div', { class: 'toggle-row-text' }, h('div', { class: 'toggle-row-label', text: label }), description ? h('div', { class: 'toggle-row-desc', text: description }) : null, on === null ? h('div', { class: 'toggle-row-desc', text: 'Not available on this PC.' }) : null, note),
    h('label', { class: 'switch' }, input, h('span', { class: 'switch-track' })));
}

async function loadDebloat() {
  const body = clear($('debloatBody'));
  body.append(h('div', { class: 'feed-empty', text: 'Checking current settings…' }));
  const [catalog, states, apps, appStates] = await Promise.all([
    call('debloat.catalog').catch(() => []),
    call('debloat.states').catch(() => ({})),
    api.userApps('catalog'),
    api.userApps('states'),
  ]);
  clear(body).append(
    ...section('Privacy and telemetry',
      ...catalog.map((f) => switchRow({
        label: f.label,
        description: f.description,
        on: states[f.id] === 'on' ? true : states[f.id] === 'off' ? false : null,
        disabled: !state.isAdmin,
        onChange: async (enable) => {
          try {
            const r = await call('debloat.set', { id: f.id, enable });
            return { ok: r.ok, message: r.note, error: r.error };
          } catch (err) {
            return { ok: false, error: explainError(err) };
          }
        },
      }))),
    ...section('Preinstalled apps (for your account)',
      h('p', { class: 'muted small', text: 'Switch off to uninstall for your account. Switching back on tries to restore it; if Windows has already cleaned up the files, you\'ll get a link to reinstall from the Microsoft Store.' }),
      ...apps.map((a) => switchRow({
        label: a.label,
        on: appStates[a.id] === 'installed' ? true : appStates[a.id] === 'removed' ? false : null,
        onChange: (install) => api.userApps('set', a.id, install),
      }))),
  );
}

// ---------- settings ----------
const TRUST_TYPE_LABELS = { account: 'Accounts', program: 'Programs', publisher: 'Publishers', address: 'Addresses', startup: 'Startup items', kind: 'Muted alert types' };

async function loadSettings() {
  const body = clear($('settingsBody'));
  let settings, rules, watchlist, update;
  try {
    [settings, rules, watchlist, update] = await Promise.all([call('settings.get'), call('trust.list'), call('watchlist.get'), call('update.status')]);
  } catch (err) {
    body.append(h('div', { class: 'feed-empty', text: explainError(err) }));
    return;
  }
  state.settings = settings;
  const admin = state.isAdmin;

  const grouped = {};
  rules.forEach((r) => (grouped[r.type] ||= []).push(r));
  const trustSection = Object.keys(grouped).length
    ? Object.entries(grouped).flatMap(([type, list]) => [
      h('div', { class: 'subsection-title', text: TRUST_TYPE_LABELS[type] || type }),
      h('ul', { class: 'user-list' }, list.map((r) => h('li', {},
        h('span', {}, r.label || r.value, r.createdBy ? h('span', { class: 'muted small', text: ` · added by ${r.createdBy}` }) : null),
        h('button', {
          text: 'Remove', disabled: !admin,
          onclick: async () => {
            try {
              await call('trust.remove', { id: r.id });
              toast('Trust removed. You\'ll be alerted about this again.');
              loadSettings();
            } catch (err) {
              info("Couldn't remove", explainError(err));
            }
          },
        })))),
    ])
    : [h('p', { class: 'muted', text: 'Nothing trusted yet. Use the Trust button on an alert to stop being alerted about something you recognize.' })];

  const ringOptions = [['early', 'Early: get new versions first'], ['standard', 'Standard (recommended)'], ['delayed', 'Delayed: wait a week after everyone else']];
  const ringSelect = h('select', { disabled: !admin, 'aria-label': 'Update timing' }, ringOptions.map(([v, l]) => h('option', { value: v, text: l, selected: settings.updateRing === v })));
  ringSelect.addEventListener('change', () => updateSetting({ updateRing: ringSelect.value }));

  const notifySelect = h('select', { disabled: !admin, 'aria-label': 'Notification level' },
    [['critical', 'Only urgent alerts'], ['warn', 'Urgent alerts and things to check (recommended)'], ['info', 'Everything']].map(([v, l]) => h('option', { value: v, text: l, selected: settings.notifyMinSeverity === v })));
  notifySelect.addEventListener('change', () => updateSetting({ notifyMinSeverity: notifySelect.value }));

  const off = settings.offsite;
  const intervalSelect = h('select', { disabled: !admin || !off.destination, 'aria-label': 'Backup interval' }, [[5, 'every 5 minutes'], [15, 'every 15 minutes'], [60, 'every hour']].map(([v, l]) => h('option', { value: String(v), text: l, selected: off.intervalMinutes === v })));
  intervalSelect.addEventListener('change', () => call('offsite.setInterval', { minutes: Number(intervalSelect.value) }).then(loadSettings, (e) => info("Couldn't change", explainError(e))));

  body.append(
    ...section('Trusted',
      h('p', { class: 'muted small', text: 'Things you\'ve told Watchtower are expected. They\'re still logged in History, just without alerting you.' }),
      ...trustSection),
    ...section('Notifications', h('div', { class: 'setting-row' }, h('span', { text: 'Pop-up notifications for' }), notifySelect)),
    ...section('Off-machine backup',
      h('p', { class: 'muted small', text: 'Keeps a copy of the history log in a folder you choose, ideally one synced to OneDrive, Dropbox or Google Drive, or a network drive. If this PC is wiped or tampered with, the copy survives.' }),
      switchRow({
        label: 'Back up history automatically',
        description: off.destination ? `To ${off.destination}. Syncs on a schedule and within seconds of any urgent alert.` : 'Choose a folder first.',
        on: off.enabled,
        disabled: !admin || !off.destination,
        onChange: async (enabled) => {
          try {
            await call('offsite.setEnabled', { enabled });
            return { ok: true };
          } catch (err) {
            return { ok: false, error: explainError(err) };
          }
        },
      }),
      h('div', { class: 'setting-row' },
        h('span', { class: 'muted small', text: off.lastSync ? `Last backed up ${new Date(off.lastSync).toLocaleString()}` : 'Never backed up.' }),
        off.lastError ? h('span', { class: 'error small', text: off.lastError }) : null),
      h('div', { class: 'button-row' },
        h('button', { class: 'action-btn', text: 'Choose folder…', disabled: !admin, onclick: async () => { const r = await api.chooseOffsiteFolder(); if (r.ok) loadSettings(); else if (!r.canceled) info("Couldn't use that folder", r.error); } }),
        h('button', { class: 'action-btn', text: 'Back up now', disabled: !admin || !off.destination, onclick: async () => { try { const r = await call('offsite.syncNow'); if (r.ok) toast(`Backed up to ${r.targetDir}`); else info('Backup failed', r.error); } catch (err) { info('Backup failed', explainError(err)); } loadSettings(); } }),
        intervalSelect)),
    ...section('Updates',
      h('p', { class: 'muted small', text: update.configured ? update.message : 'Automatic updates aren\'t set up in this build.' }),
      switchRow({ label: 'Install updates automatically', description: 'New versions reach a small group of PCs first and only go wider once they\'ve proven stable. If an update misbehaves on this PC, Watchtower puts the previous version back by itself.', on: settings.autoUpdate, disabled: !admin, onChange: (v) => updateSetting({ autoUpdate: v }) }),
      h('div', { class: 'setting-row' }, h('span', { text: 'When to get new versions' }), ringSelect),
      h('div', { class: 'button-row' },
        h('button', { class: 'action-btn', text: 'Check now', disabled: !update.configured, onclick: async () => { try { const s = await call('update.check'); toast(s.message); } catch (err) { info("Couldn't check", explainError(err)); } } }),
        update.available ? h('button', { class: 'primary-btn', text: `Install ${update.available}`, disabled: !admin, onclick: () => call('update.install').then((s) => toast(s.message), (e) => info("Couldn't install", explainError(e))) }) : null)),
    ...section('Crash reports',
      settings.crashReportsAvailable
        ? switchRow({ label: 'Send crash reports', description: 'If Watchtower crashes, send the technical details of the crash (never your alerts, history, file names or account names) so it can be fixed.', on: settings.crashReports, disabled: !admin, onChange: (v) => updateSetting({ crashReports: v }) })
        : h('p', { class: 'muted small', text: 'Crash details are kept on this PC only.' })),
    ...section('Remote-access programs to watch for',
      h('p', { class: 'muted small', text: 'Watchtower alerts when any of these start. Add any tool it doesn\'t know, or turn off one you use every day.' }),
      watchlistEditor(watchlist, admin)),
    ...section('Setup', h('div', { class: 'button-row' }, h('button', { class: 'action-btn', text: 'Run the setup guide again', disabled: !admin, onclick: openWizard }))),
  );
}

async function updateSetting(patch) {
  try {
    state.settings = await call('settings.update', patch);
    toast('Saved.');
    renderBanner();
    return { ok: true };
  } catch (err) {
    return { ok: false, error: explainError(err) };
  }
}

function watchlistEditor(info_, admin) {
  const input = h('input', { type: 'text', placeholder: 'Program name, e.g. quickassist.exe', disabled: !admin, 'aria-label': 'Program to watch for' });
  const add = async () => {
    if (!input.value.trim()) return;
    try {
      await call('watchlist.add', { name: input.value.trim() });
      loadSettings();
    } catch (err) {
      info("Couldn't add", explainError(err));
    }
  };
  input.addEventListener('keydown', (e) => e.key === 'Enter' && add());
  const change = (method, name) => call(method, { name }).then(loadSettings, (e) => info("Couldn't change", explainError(e)));
  return h('div', {},
    h('div', { class: 'user-input' }, input, h('button', { class: 'toggle-btn', text: 'Add', disabled: !admin, onclick: add })),
    h('ul', { class: 'user-list columns' },
      info_.custom.map((n) => h('li', {}, h('span', {}, n, ' ', h('span', { class: 'tag yes', text: 'added by you' })), h('button', { text: 'Remove', disabled: !admin, onclick: () => change('watchlist.remove', n) }))),
      info_.defaults.map((d) => h('li', { class: d.disabled ? 'off' : '' }, h('span', { text: d.name }), h('button', { text: d.disabled ? 'Watch again' : 'Don\'t watch', disabled: !admin, onclick: () => change(d.disabled ? 'watchlist.restore' : 'watchlist.remove', d.name) })))));
}

// ---------- tabs ----------
function selectTab(name) {
  document.querySelectorAll('.tab').forEach((b) => b.classList.toggle('active', b.dataset.tab === name));
  document.querySelectorAll('.panel').forEach((p) => p.classList.toggle('hidden', p.id !== `panel-${name}`));
  if (name === 'history') loadHistory();
  if (name === 'network') loadBlocked();
  if (name === 'exposure' && !exposureLoaded) runExposure();
  if (name === 'debloat') loadDebloat();
  if (name === 'settings') loadSettings();
}
document.querySelectorAll('.tab').forEach((btn) => btn.addEventListener('click', () => selectTab(btn.dataset.tab)));

// ---------- setup wizard ----------
const REMOTE_TOOLS = [
  ['Remote Desktop (connecting out to other PCs)', ['mstsc.exe']],
  ['Quick Assist', ['quickassist.exe']],
  ['TeamViewer', ['teamviewer.exe', 'teamviewer_service.exe']],
  ['AnyDesk', ['anydesk.exe']],
  ['Chrome Remote Desktop', ['remoting_host.exe', 'remotingdesktophost.exe']],
  ['RustDesk', ['rustdesk.exe']],
  ['Splashtop', ['splashtopstreamer.exe', 'srserver.exe', 'srfeature.exe']],
  ['ConnectWise / ScreenConnect', ['screenconnect.windowsclient.exe', 'connectwisecontrol.clienthost.exe']],
];

const wizard = { step: 0, accounts: [], data: null };

function wizardSteps() {
  const d = wizard.data;
  return [
    {
      title: 'Welcome to Watchtower',
      render: () => [
        h('p', { text: 'Watchtower keeps an eye on this PC for signs that someone else is using it or reaching into it: remote sign-ins, remote-control programs, new programs that behave suspiciously, unexpected network connections, and camera or microphone use.' }),
        h('ul', { class: 'plain-list' },
          h('li', { text: 'It runs in the background from the moment Windows starts, even before anyone signs in.' }),
          h('li', { text: 'It never sends your activity anywhere. Everything stays on this PC unless you choose a backup folder.' }),
          h('li', { text: 'It keeps a history that can\'t be quietly edited, so you can check what happened while you were away.' })),
        h('p', { class: 'muted small', text: 'Watchtower isn\'t antivirus. It works alongside Microsoft Defender, not instead of it. This takes about a minute.' }),
      ],
    },
    {
      title: 'Who is allowed to sign in remotely?',
      render: () => [
        h('p', { text: 'If anyone signs in to this PC from another computer (for example with Remote Desktop), Watchtower will tell you. Tick the accounts that are allowed to do that. Anyone else will be flagged as urgent.' }),
        h('p', { class: 'muted small', text: 'If nobody ever signs in to this PC remotely, leave them all unticked.' }),
        h('div', { class: 'check-list' }, wizard.accounts.map((a) => checkbox(`${a.name}${a.isYou ? ' (you)' : ''}${a.isAdmin ? ', administrator' : ''}`, d.trustedAccounts.has(a.name), (on) => (on ? d.trustedAccounts.add(a.name) : d.trustedAccounts.delete(a.name))))),
      ],
    },
    {
      title: 'Do you use any remote-control programs?',
      render: () => [
        h('p', { text: 'Scammers often ask people to install programs like these so they can take over the PC. Watchtower alerts whenever one starts.' }),
        h('p', { text: 'If you use one of them yourself, tick it so you\'re not alerted every time. If you\'re not sure, leave it unticked. An extra alert is better than a missed one.' }),
        h('div', { class: 'check-list' }, REMOTE_TOOLS.map(([label, exes]) => checkbox(label, exes.every((e) => d.usedTools.has(e)), (on) => exes.forEach((e) => (on ? d.usedTools.add(e) : d.usedTools.delete(e)))))),
      ],
    },
    {
      title: 'Learning what\'s normal',
      render: () => [
        h('p', { text: 'Every PC has dozens of programs that connect to the internet or run for the first time in a normal day. For the first 24 hours Watchtower can quietly learn these instead of alerting you about each one.' }),
        h('p', { text: 'Serious things, like someone signing in remotely, a new program opening a door into the PC, or something adding itself to startup, still alert straight away.' }),
        checkbox('Learn for 24 hours first (recommended)', d.learning, (on) => (d.learning = on)),
      ],
    },
    {
      title: 'Updates',
      render: () => [
        h('p', { text: 'Watchtower updates itself. New versions go to a small group of PCs first and only reach everyone once they\'ve proven stable. If an update misbehaves on this PC, the previous version is put back automatically.' }),
        checkbox('Install updates automatically (recommended)', d.autoUpdate, (on) => (d.autoUpdate = on)),
        h('div', { class: 'radio-list' }, [['early', 'Early', 'Get new versions as soon as they start rolling out.'], ['standard', 'Standard (recommended)', 'Get new versions once they\'ve reached some PCs without problems.'], ['delayed', 'Delayed', 'Wait until a version has been out for everyone for a week.']]
          .map(([v, l, desc]) => radio('ring', v, l, desc, d.updateRing === v, () => (d.updateRing = v)))),
        state.settings?.crashReportsAvailable
          ? checkbox('Send crash reports if Watchtower crashes (only the technical details of the crash, never your alerts, history or names)', d.crashReports, (on) => (d.crashReports = on))
          : null,
      ],
    },
    {
      title: 'Keep a copy somewhere safe (optional)',
      render: () => [
        h('p', { text: 'If someone takes over this PC, the first thing they may do is delete the evidence. Watchtower can keep a copy of its history in a folder that\'s synced to the cloud (OneDrive, Dropbox, Google Drive) or on another drive.' }),
        h('div', { class: 'button-row' },
          h('button', { class: 'action-btn', text: d.backupFolder ? `Change folder (${d.backupFolder})` : 'Choose a folder…', onclick: async () => {
            const r = await api.chooseOffsiteFolder();
            if (r.ok) {
              d.backupFolder = r.result.offsite.destination;
              renderWizard();
            } else if (!r.canceled) info("Couldn't use that folder", r.error);
          } })),
        h('p', { class: 'muted small', text: 'You can skip this and set it up later in Settings.' }),
      ],
    },
    {
      title: 'All set',
      render: () => [
        h('p', { text: 'Watchtower is watching. Here\'s what you chose:' }),
        h('ul', { class: 'plain-list' },
          h('li', { text: d.trustedAccounts.size ? `Remote sign-ins allowed for: ${[...d.trustedAccounts].join(', ')}` : 'No accounts are expected to sign in remotely.' }),
          h('li', { text: d.usedTools.size ? `Remote-control programs you use won't alert: ${REMOTE_TOOLS.filter(([, e]) => e.every((x) => d.usedTools.has(x))).map(([l]) => l).join(', ')}` : 'Every remote-control program will alert.' }),
          h('li', { text: d.learning ? 'Learning what\'s normal for the next 24 hours.' : 'Alerting about everything from now on.' }),
          h('li', { text: `Updates: ${d.autoUpdate ? 'automatic' : 'manual'}, ${d.updateRing} timing.` }),
          h('li', { text: d.backupFolder ? `History backed up to ${d.backupFolder}.` : 'No backup folder yet.' })),
        h('p', { class: 'muted small', text: 'When something happens you\'ll get a notification. Open an alert and choose "What does this mean?" for plain-English guidance.' }),
      ],
    },
  ];
}

function checkbox(label, checked, onChange) {
  const input = h('input', { type: 'checkbox', checked });
  input.addEventListener('change', () => onChange(input.checked));
  return h('label', { class: 'check' }, input, h('span', { text: label }));
}

function radio(name, value, label, desc, checked, onChange) {
  const input = h('input', { type: 'radio', name, value, checked });
  input.addEventListener('change', onChange);
  return h('label', { class: 'check' }, input, h('span', {}, h('strong', { text: label }), h('span', { class: 'muted small block', text: desc })));
}

function renderWizard() {
  const steps = wizardSteps();
  const step = steps[wizard.step];
  $('wizardTitle').textContent = step.title;
  clear($('wizardBody')).append(...step.render().filter(Boolean));
  clear($('wizardProgress')).append(...steps.map((_, i) => h('span', { class: i === wizard.step ? 'dot active' : i < wizard.step ? 'dot done' : 'dot' })));
  $('wizardBack').style.visibility = wizard.step === 0 ? 'hidden' : 'visible';
  $('wizardNext').textContent = wizard.step === steps.length - 1 ? 'Start watching' : wizard.step === 5 && !wizard.data.backupFolder ? 'Skip' : 'Next';
  $('wizardNext').focus();
}

async function openWizard() {
  if (!state.isAdmin) {
    info('Setup needed', 'Watchtower needs to be set up by an administrator of this PC. It\'s already monitoring with safe defaults in the meantime.');
    return;
  }
  const [accounts, rules] = await Promise.all([call('accounts.list').catch(() => []), call('trust.list').catch(() => [])]);
  const s = state.settings || {};
  wizard.accounts = accounts;
  wizard.step = 0;
  wizard.data = {
    trustedAccounts: new Set(rules.filter((r) => r.type === 'account').map((r) => r.value)),
    usedTools: new Set(),
    learning: true,
    autoUpdate: s.autoUpdate ?? true,
    updateRing: s.updateRing || 'standard',
    crashReports: s.crashReports ?? false,
    backupFolder: s.offsite?.destination || null,
  };
  $('wizard').classList.remove('hidden');
  renderWizard();
}

$('wizardBack').addEventListener('click', () => {
  wizard.step = Math.max(0, wizard.step - 1);
  renderWizard();
});

$('wizardNext').addEventListener('click', async () => {
  const steps = wizardSteps();
  if (wizard.step < steps.length - 1) {
    wizard.step += 1;
    renderWizard();
    return;
  }
  const d = wizard.data;
  try {
    state.settings = await call('setup.complete', {
      trustedAccounts: [...d.trustedAccounts],
      usedTools: [...d.usedTools],
      learning: d.learning,
      autoUpdate: d.autoUpdate,
      updateRing: d.updateRing,
      crashReports: d.crashReports,
    });
    if (d.backupFolder) await call('offsite.setEnabled', { enabled: true });
    state.setupCompleted = true;
    $('wizard').classList.add('hidden');
    renderBanner();
    toast('Watchtower is set up and watching.');
  } catch (err) {
    info("Setup couldn't be saved", explainError(err));
  }
});

// ---------- start ----------
renderBanner();
api.serviceStatus().then(({ connected }) => { if (connected) onConnected(); });
