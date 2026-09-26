const fs = require('fs');
const path = require('path');
const { runPowerShell } = require('./lib/exec');
const { getProcessDetails } = require('./lib/processes');

function toArray(parsed) {
  if (parsed == null) return [];
  return Array.isArray(parsed) ? parsed : [parsed];
}

async function psJson(script, timeout = 20_000) {
  try {
    const out = await runPowerShell(script, { timeout });
    return toArray(JSON.parse(out || 'null'));
  } catch {
    return [];
  }
}

// ---------- Listening ports: the exposure question ----------
// A port bound to 127.0.0.1 cannot be reached from another machine. One bound
// to 0.0.0.0 or :: is reachable from the whole network. That distinction is
// what actually determines exposure, not whether something is listening.

function classifyBinding(addr) {
  if (!addr) return 'unknown';
  if (addr === '127.0.0.1' || addr === '::1') return 'local-only';
  if (addr === '0.0.0.0' || addr === '::' || addr === '*') return 'all-interfaces';
  return 'specific-interface';
}

const NOTABLE_PORTS = {
  21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP', 135: 'RPC',
  139: 'NetBIOS', 445: 'SMB file sharing', 1433: 'SQL Server',
  3306: 'MySQL', 3389: 'Remote Desktop', 5432: 'PostgreSQL',
  5900: 'VNC', 5985: 'WinRM (HTTP)', 5986: 'WinRM (HTTPS)',
  6379: 'Redis', 27017: 'MongoDB',
};

async function getListeningExposure() {
  const [rows, procs] = await Promise.all([
    psJson(
      'Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue | ' +
        'Select-Object LocalAddress,LocalPort,OwningProcess | ConvertTo-Json -Compress'
    ),
    getProcessDetails({ fresh: true }).catch(() => []),
  ]);

  const byPid = new Map(procs.map((p) => [p.pid, p]));
  const seen = new Map();

  rows.forEach((r) => {
    const scope = classifyBinding(r.LocalAddress);
    const key = `${r.LocalPort}|${scope}|${r.OwningProcess}`;
    if (seen.has(key)) return;
    const proc = byPid.get(r.OwningProcess);
    seen.set(key, {
      port: r.LocalPort,
      address: r.LocalAddress,
      scope,
      exposed: scope === 'all-interfaces' || scope === 'specific-interface',
      pid: r.OwningProcess,
      name: proc?.name || `pid:${r.OwningProcess}`,
      path: proc?.path || null,
      service: NOTABLE_PORTS[r.LocalPort] || null,
    });
  });

  return [...seen.values()].sort((a, b) => {
    if (a.exposed !== b.exposed) return a.exposed ? -1 : 1;
    return a.port - b.port;
  });
}

// ---------- Adapters: are you behind NAT or directly on the internet? ----------

function classifyIp(ip) {
  if (!ip) return 'unknown';
  if (/^127\./.test(ip)) return 'loopback';
  if (/^169\.254\./.test(ip)) return 'link-local'; // no DHCP reply
  if (/^10\./.test(ip)) return 'private';
  if (/^192\.168\./.test(ip)) return 'private';
  if (/^172\.(1[6-9]|2\d|3[01])\./.test(ip)) return 'private';
  if (/^100\.(6[4-9]|[7-9]\d|1[01]\d|12[0-7])\./.test(ip)) return 'cgnat';
  if (ip.includes(':')) return ip.startsWith('fe80') ? 'link-local' : 'ipv6';
  return 'public'; // a public IP directly on the adapter means no NAT in front
}

async function getAdapters() {
  const rows = await psJson(
    'Get-NetIPAddress -ErrorAction SilentlyContinue | ' +
      'Where-Object { $_.AddressState -eq "Preferred" } | ' +
      'Select-Object IPAddress,InterfaceAlias,AddressFamily | ConvertTo-Json -Compress'
  );
  return rows
    .map((r) => ({
      ip: r.IPAddress,
      adapter: r.InterfaceAlias,
      kind: classifyIp(r.IPAddress),
    }))
    .filter((r) => r.kind !== 'loopback');
}

// ---------- Firewall ----------

async function getFirewall() {
  const rows = await psJson(
    'Get-NetFirewallProfile -ErrorAction SilentlyContinue | ' +
      'Select-Object Name,Enabled,DefaultInboundAction | ConvertTo-Json -Compress'
  );
  return rows.map((r) => ({
    profile: r.Name,
    enabled: r.Enabled === true || r.Enabled === 1 || r.Enabled === 'True',
    defaultInbound: String(r.DefaultInboundAction),
  }));
}

// ---------- Remote Desktop ----------

async function getRdpStatus() {
  const rows = await psJson(
    "$deny = (Get-ItemProperty -Path 'HKLM:\\System\\CurrentControlSet\\Control\\Terminal Server' -Name fDenyTSConnections -ErrorAction SilentlyContinue).fDenyTSConnections; " +
      "$port = (Get-ItemProperty -Path 'HKLM:\\System\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp' -Name PortNumber -ErrorAction SilentlyContinue).PortNumber; " +
      "$nla = (Get-ItemProperty -Path 'HKLM:\\System\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp' -Name UserAuthentication -ErrorAction SilentlyContinue).UserAuthentication; " +
      '[PSCustomObject]@{ deny = $deny; port = $port; nla = $nla } | ConvertTo-Json -Compress'
  );
  const r = rows[0] || {};
  return {
    enabled: r.deny === 0,
    port: r.port ?? 3389,
    // Network Level Authentication forces auth before a session is created.
    // Without it, an unauthenticated attacker reaches the logon screen itself.
    nlaRequired: r.nla === 1,
  };
}

// ---------- DNS: hijack check ----------

async function getDns() {
  const rows = await psJson(
    'Get-DnsClientServerAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue | ' +
      'Where-Object { $_.ServerAddresses.Count -gt 0 } | ' +
      'Select-Object InterfaceAlias,ServerAddresses | ConvertTo-Json -Compress'
  );
  return rows.map((r) => ({
    adapter: r.InterfaceAlias,
    servers: toArray(r.ServerAddresses),
  }));
}

// ---------- Hosts file: classic redirection vector ----------

function getHostsEntries() {
  const hostsPath = path.join(
    process.env.SystemRoot || 'C:\\Windows',
    'System32',
    'drivers',
    'etc',
    'hosts'
  );
  try {
    const text = fs.readFileSync(hostsPath, 'utf8');
    return text
      .split(/\r?\n/)
      .map((l) => l.trim())
      .filter((l) => l && !l.startsWith('#'))
      // Default loopback mappings aren't interesting; anything else is.
      .filter((l) => !/^(127\.0\.0\.1|::1)\s+localhost$/i.test(l))
      .map((line) => {
        const [ip, ...names] = line.split(/\s+/);
        return { ip, hosts: names.join(' '), line };
      });
  } catch (err) {
    return [];
  }
}

// ---------- Proxy: traffic interception check ----------

async function getProxy() {
  const rows = await psJson(
    "$k = 'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings'; " +
      '$p = Get-ItemProperty -Path $k -ErrorAction SilentlyContinue; ' +
      '[PSCustomObject]@{ enabled = $p.ProxyEnable; server = $p.ProxyServer; autoConfig = $p.AutoConfigURL } | ConvertTo-Json -Compress'
  );
  const r = rows[0] || {};
  let winhttp = null;
  try {
    const out = await runPowerShell('netsh winhttp show proxy', { timeout: 10_000 });
    winhttp = out.trim();
  } catch {
    winhttp = null;
  }
  return {
    // A proxy you didn't set means something can read your traffic.
    enabled: r.enabled === 1,
    server: r.server || null,
    autoConfigUrl: r.autoConfig || null,
    winhttp,
  };
}

// ---------- VPN / tunnel adapters ----------

const KNOWN_VPN_HINTS = [
  'wireguard', 'openvpn', 'tap-windows', 'tailscale', 'zerotier',
  'nordlynx', 'expressvpn', 'proton', 'mullvad', 'hamachi', 'softether',
  'cisco anyconnect', 'globalprotect', 'forticlient', 'pulse', 'radmin vpn',
  'wan miniport', 'teredo', 'isatap',
];

async function getTunnels() {
  const rows = await psJson(
    'Get-NetAdapter -IncludeHidden -ErrorAction SilentlyContinue | ' +
      'Select-Object Name,InterfaceDescription,Status,MediaType | ConvertTo-Json -Compress'
  );
  return rows
    .map((r) => {
      const hay = `${r.Name} ${r.InterfaceDescription}`.toLowerCase();
      const hint = KNOWN_VPN_HINTS.find((h) => hay.includes(h));
      const isTunnelish =
        !!hint || /tunnel|vpn|tap|tun\b/i.test(hay) || r.MediaType === 'Tunnel';
      if (!isTunnelish) return null;
      return {
        name: r.Name,
        description: r.InterfaceDescription,
        status: r.Status,
        active: r.Status === 'Up',
        recognized: !!hint,
      };
    })
    .filter(Boolean);
}

// ---------- SMB shares ----------

async function getShares() {
  const rows = await psJson(
    'Get-SmbShare -ErrorAction SilentlyContinue | ' +
      'Select-Object Name,Path,Description | ConvertTo-Json -Compress'
  );
  // ADMIN$, C$, IPC$ are built-in administrative shares. They're always there
  // and aren't themselves a finding, so they're marked rather than hidden.
  return rows.map((r) => ({
    name: r.Name,
    path: r.Path,
    administrative: /\$$/.test(r.Name),
  }));
}

// ---------- Findings roll-up ----------

function buildFindings(data) {
  const findings = [];

  data.listening
    .filter((l) => l.exposed)
    .forEach((l) => {
      const label = l.service ? `${l.service} (port ${l.port})` : `Port ${l.port}`;
      findings.push({
        severity: l.service ? 'critical' : 'warn',
        title: `${label} is reachable from the network`,
        detail: `${l.name} is listening on ${l.address}. Anything on your network — and the internet, if your router forwards this port — can attempt to connect.`,
      });
    });

  data.adapters
    .filter((a) => a.kind === 'public')
    .forEach((a) => {
      findings.push({
        severity: 'critical',
        title: 'This machine has a public IP directly on an adapter',
        detail: `${a.adapter} holds ${a.ip}, which is a public address. There is no router/NAT shielding you — every exposed port is reachable from the internet.`,
      });
    });

  data.firewall
    .filter((f) => !f.enabled)
    .forEach((f) => {
      findings.push({
        severity: 'critical',
        title: `Firewall is OFF for the ${f.profile} profile`,
        detail: 'Inbound connections are not being filtered on this network type.',
      });
    });

  if (data.rdp.enabled) {
    findings.push({
      severity: data.rdp.nlaRequired ? 'warn' : 'critical',
      title: `Remote Desktop is enabled on port ${data.rdp.port}`,
      detail: data.rdp.nlaRequired
        ? 'Network Level Authentication is on, which is the safer configuration. Turn RDP off entirely if you do not use it.'
        : 'Network Level Authentication is OFF — an unauthenticated attacker can reach the logon screen itself. Enable NLA, or disable RDP if unused.',
    });
  }

  if (data.proxy.enabled && data.proxy.server) {
    findings.push({
      severity: 'critical',
      title: 'A system proxy is configured',
      detail: `Traffic is routed through ${data.proxy.server}. If you did not set this up, something may be reading your web traffic.`,
    });
  }
  if (data.proxy.autoConfigUrl) {
    findings.push({
      severity: 'warn',
      title: 'A proxy auto-config URL is set',
      detail: `Proxy settings are pulled from ${data.proxy.autoConfigUrl}. Verify you recognize this.`,
    });
  }

  if (data.hosts.length) {
    findings.push({
      severity: 'warn',
      title: `${data.hosts.length} custom hosts-file entr${data.hosts.length === 1 ? 'y' : 'ies'}`,
      detail:
        'The hosts file can redirect domains to different servers. Ad-blockers use this legitimately, but so does malware. Review the entries below.',
    });
  }

  data.tunnels
    .filter((t) => t.active && !t.recognized)
    .forEach((t) => {
      findings.push({
        severity: 'warn',
        title: 'Unrecognized tunnel adapter is active',
        detail: `"${t.name}" (${t.description}) is up but doesn't match known VPN software. If you didn't install a VPN, investigate this.`,
      });
    });

  data.shares
    .filter((s) => !s.administrative)
    .forEach((s) => {
      findings.push({
        severity: 'warn',
        title: `Folder shared on the network: ${s.name}`,
        detail: `${s.path} is accessible to other machines. Remove the share if you don't need it.`,
      });
    });

  const dnsFlat = data.dns.flatMap((d) => d.servers);
  if (dnsFlat.length && dnsFlat.every((s) => classifyIp(s) === 'public')) {
    findings.push({
      severity: 'info',
      title: 'DNS is set to public resolvers',
      detail:
        `Using ${dnsFlat.join(', ')}. This is normal if you chose them (Cloudflare, Google, Quad9). ` +
        'If you did not, DNS redirection can silently send you to fake sites.',
    });
  }

  return findings.sort((a, b) => {
    const rank = { critical: 0, warn: 1, info: 2 };
    return rank[a.severity] - rank[b.severity];
  });
}

async function scan() {
  const [listening, adapters, firewall, rdp, dns, proxy, tunnels, shares] = await Promise.all([
    getListeningExposure(),
    getAdapters(),
    getFirewall(),
    getRdpStatus(),
    getDns(),
    getProxy(),
    getTunnels(),
    getShares(),
  ]);
  const hosts = getHostsEntries();
  const data = { listening, adapters, firewall, rdp, dns, hosts, proxy, tunnels, shares };
  return { ...data, findings: buildFindings(data), scannedAt: new Date().toISOString() };
}

module.exports = { scan, classifyIp, classifyBinding };
