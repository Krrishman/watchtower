const fs = require('fs');
const path = require('path');
const { DATA_DIR } = require('./paths');

const DIR = DATA_DIR;

function filePath(name) {
  return path.join(DIR, `${name}.json`);
}

function loadJson(name, fallback) {
  try {
    const raw = fs.readFileSync(filePath(name), 'utf8');
    return JSON.parse(raw);
  } catch {
    return fallback;
  }
}

function saveJson(name, data) {
  try {
    if (!fs.existsSync(DIR)) fs.mkdirSync(DIR, { recursive: true });
    fs.writeFileSync(filePath(name), JSON.stringify(data), 'utf8');
  } catch {
    // Non-fatal: worst case we re-check/re-alert on the same item after a restart.
  }
}

function loadSet(name) {
  return new Set(loadJson(name, []));
}

function saveSet(name, set) {
  saveJson(name, [...set]);
}

module.exports = { loadJson, saveJson, loadSet, saveSet };
