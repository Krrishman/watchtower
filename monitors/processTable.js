const { getProcessDetails } = require('./lib/processes');
const { checkSignatures } = require('./lib/signature');
const { loadJson, saveJson } = require('./lib/store');
const network = require('./network');

const SIG_CACHE_KEY = 'signature-cache';
let sigCache = loadJson(SIG_CACHE_KEY, {});
const MAX_SIG_CHECKS_PER_TICK = 40; // batching guard so one tick never spawns a huge PS call

async function check() {
  const procs = await getProcessDetails();
  const activePids = network.getActivePids();

  const unknownPaths = [
    ...new Set(procs.map((p) => p.path).filter((p) => p && !(p in sigCache))),
  ].slice(0, MAX_SIG_CHECKS_PER_TICK);

  if (unknownPaths.length) {
    const results = await checkSignatures(unknownPaths);
    Object.assign(sigCache, results);
    saveJson(SIG_CACHE_KEY, sigCache);
  }

  const snapshot = procs
    .filter((p) => p.path) // system/protected processes with no visible path are skipped
    .map((p) => {
      const status = sigCache[p.path] || 'Unknown';
      return {
        pid: p.pid,
        name: p.name,
        path: p.path,
        signed: status === 'Valid',
        signatureStatus: status,
        networked: activePids.has(p.pid),
      };
    })
    .sort((a, b) => (a.networked === b.networked ? 0 : a.networked ? -1 : 1));

  // This monitor is a viewer, not an alerter — the newProgramWatch and
  // processes (watchlist) monitors are what raise alerts about processes.
  return { alerts: [], snapshot };
}

module.exports = { check };
