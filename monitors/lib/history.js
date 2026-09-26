const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { DATA_DIR } = require('./paths');

const DIR = DATA_DIR;
const FILE = path.join(DIR, 'history.jsonl');
const ANCHOR_FILE = path.join(DIR, 'history-anchor.json');
const HIGHWATER_FILE = path.join(DIR, 'history-highwater.json');
const MAX_LINES = 20_000; // trim well before this to keep file/reads fast

const GENESIS = '0'.repeat(64);

// ---------- Hash chain ----------
// Each entry stores the hash of the previous entry, so editing or deleting any
// past line breaks every hash after it. This doesn't PREVENT tampering — an
// attacker with admin can still rewrite the file — but it makes silent edits
// detectable, which is the part that matters for an audit record.

function entryHash(entry, prevHash) {
  const payload = JSON.stringify({
    seq: entry.seq,
    time: entry.time,
    source: entry.source,
    severity: entry.severity,
    title: entry.title,
    detail: entry.detail,
    prevHash,
  });
  return crypto.createHash('sha256').update(payload).digest('hex');
}

function readAnchor() {
  try {
    return JSON.parse(fs.readFileSync(ANCHOR_FILE, 'utf8'));
  } catch {
    return { seq: 0, hash: GENESIS };
  }
}

function writeAnchor(anchor) {
  try {
    if (!fs.existsSync(DIR)) fs.mkdirSync(DIR, { recursive: true });
    fs.writeFileSync(ANCHOR_FILE, JSON.stringify(anchor), 'utf8');
  } catch {
    // Non-fatal.
  }
}

// A chain is internally consistent even if its newest entries are deleted, so
// the chain alone can't detect tail truncation — an attacker could simply drop
// the lines recording what they did. Persisting the highest sequence number
// ever written, separately, makes that removal visible.
function readHighWater() {
  try {
    return JSON.parse(fs.readFileSync(HIGHWATER_FILE, 'utf8')).seq || 0;
  } catch {
    return 0;
  }
}

function writeHighWater(seq) {
  try {
    if (!fs.existsSync(DIR)) fs.mkdirSync(DIR, { recursive: true });
    fs.writeFileSync(HIGHWATER_FILE, JSON.stringify({ seq }), 'utf8');
  } catch {
    // Non-fatal.
  }
}

function rawLines() {
  try {
    return fs.readFileSync(FILE, 'utf8').split('\n').filter(Boolean);
  } catch {
    return [];
  }
}

function parseLines(lines) {
  return lines
    .map((line) => {
      try {
        return JSON.parse(line);
      } catch {
        return null;
      }
    })
    .filter(Boolean);
}

// Tracks the tail of the chain so append() doesn't re-read the whole file.
let tail = null;

function loadTail() {
  if (tail) return tail;
  const entries = parseLines(rawLines());
  if (!entries.length) {
    const anchor = readAnchor();
    tail = { seq: anchor.seq, hash: anchor.hash };
  } else {
    const last = entries[entries.length - 1];
    tail = { seq: last.seq || entries.length, hash: last.hash || GENESIS };
  }
  return tail;
}

function append(entry) {
  try {
    if (!fs.existsSync(DIR)) fs.mkdirSync(DIR, { recursive: true });
    const prev = loadTail();
    const withSeq = { ...entry, seq: prev.seq + 1, prevHash: prev.hash };
    withSeq.hash = entryHash(withSeq, prev.hash);
    fs.appendFileSync(FILE, JSON.stringify(withSeq) + '\n', 'utf8');
    tail = { seq: withSeq.seq, hash: withSeq.hash };
    writeHighWater(withSeq.seq);
  } catch {
    // Non-fatal: the live feed still shows the alert even if logging fails.
  }
}

// Walks the chain from the anchor forward. Reports the first break rather than
// just pass/fail, so a tampered record points at what changed.
function verify() {
  const entries = parseLines(rawLines());
  if (!entries.length) {
    return { ok: true, checked: 0, message: 'No history recorded yet.' };
  }

  const anchor = readAnchor();
  let prevHash = anchor.hash;
  let expectedSeq = anchor.seq + 1;

  for (let i = 0; i < entries.length; i += 1) {
    const e = entries[i];

    if (e.hash == null || e.prevHash == null || e.seq == null) {
      return {
        ok: false,
        checked: i,
        message:
          `Entry ${i + 1} predates integrity checking (written by an older version). ` +
          'Entries from this point on cannot be verified.',
        unverifiable: true,
      };
    }
    if (e.seq !== expectedSeq) {
      return {
        ok: false,
        checked: i,
        message: `Sequence gap at entry ${i + 1}: expected #${expectedSeq}, found #${e.seq}. Entries appear to have been deleted.`,
      };
    }
    if (e.prevHash !== prevHash) {
      return {
        ok: false,
        checked: i,
        message: `Chain break at entry ${i + 1} (${e.time}). A previous entry was modified or removed.`,
      };
    }
    if (entryHash(e, e.prevHash) !== e.hash) {
      return {
        ok: false,
        checked: i,
        message: `Entry ${i + 1} (${e.time}) has been modified since it was written.`,
      };
    }

    prevHash = e.hash;
    expectedSeq += 1;
  }

  const lastSeq = entries[entries.length - 1].seq;
  const highWater = readHighWater();
  if (highWater > lastSeq) {
    return {
      ok: false,
      checked: entries.length,
      message:
        `The log ends at entry #${lastSeq}, but #${highWater} was written. ` +
        `${highWater - lastSeq} of the most recent entries have been deleted.`,
    };
  }

  return {
    ok: true,
    checked: entries.length,
    message: `All ${entries.length} entries verified — no signs of modification.`,
  };
}

function readAll({ limit = 1000, source = null, since = null } = {}) {
  let entries = parseLines(rawLines());
  if (source) entries = entries.filter((e) => e.source === source);
  if (since) entries = entries.filter((e) => e.time >= since);
  return entries.slice(-limit).reverse(); // most recent first
}

function trimIfNeeded() {
  try {
    const lines = rawLines();
    if (lines.length <= MAX_LINES) return;

    const keepFrom = lines.length - Math.floor(MAX_LINES / 2);
    const kept = lines.slice(keepFrom);
    const keptEntries = parseLines(kept);

    // Trimming necessarily discards the chain's history, so record where the
    // retained portion starts. Verification resumes from this anchor instead
    // of reporting a false tamper on the intentional truncation.
    if (keptEntries.length && keptEntries[0].prevHash != null) {
      writeAnchor({ seq: keptEntries[0].seq - 1, hash: keptEntries[0].prevHash });
    }
    fs.writeFileSync(FILE, kept.join('\n') + '\n', 'utf8');
    tail = null; // force reload
  } catch {
    // No file yet, or unreadable — nothing to trim.
  }
}

function csvEscape(value) {
  const str = value == null ? '' : String(value);
  return /[",\n\r]/.test(str) ? `"${str.replace(/"/g, '""')}"` : str;
}

// Exports the FULL history (not the UI's display limit) so an export is
// usable as a record rather than a snapshot of what happened to be on screen.
function exportTo(filePath, format = 'csv', { source = null } = {}) {
  const entries = readAll({ limit: Number.MAX_SAFE_INTEGER, source }).reverse(); // chronological

  if (format === 'json') {
    // Includes hash/prevHash/seq so the export is independently verifiable.
    fs.writeFileSync(filePath, JSON.stringify(entries, null, 2), 'utf8');
    return entries.length;
  }

  const header = ['seq', 'time', 'severity', 'source', 'title', 'detail', 'hash'];
  const lines = [header.join(',')];
  entries.forEach((e) => {
    lines.push(
      [e.seq, e.time, e.severity, e.source, e.title, e.detail, e.hash].map(csvEscape).join(',')
    );
  });
  // BOM so Excel opens UTF-8 correctly rather than mangling non-ASCII paths.
  fs.writeFileSync(filePath, '\uFEFF' + lines.join('\r\n'), 'utf8');
  return entries.length;
}

module.exports = { append, readAll, trimIfNeeded, exportTo, verify, FILE };
