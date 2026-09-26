const EventEmitter = require('events');
const { spawnPowerShell } = require('./lib/exec');

// Polling on a 10-30s interval misses any process that starts and exits between
// two ticks. Win32_ProcessStartTrace fires on EVERY process launch, so nothing
// short-lived slips through. It requires elevation; when that fails we fall
// back to the existing pollers rather than pretending to have coverage.

const PS_SCRIPT = `
$ErrorActionPreference = 'Stop'
try {
  Register-WmiEvent -Query "SELECT * FROM Win32_ProcessStartTrace" -SourceIdentifier WTProcStart
} catch {
  Write-Output ('{"fatal":"' + ($_.Exception.Message -replace '"',"'") + '"}')
  exit 1
}
Write-Output '{"ready":true}'
while ($true) {
  $evt = Wait-Event -SourceIdentifier WTProcStart
  $n = $evt.SourceEventArgs.NewEvent
  $obj = [PSCustomObject]@{
    name = [string]$n.ProcessName
    pid = [int]$n.ProcessID
    parentPid = [int]$n.ParentProcessID
  }
  Write-Output ($obj | ConvertTo-Json -Compress)
  Remove-Event -EventIdentifier $evt.EventIdentifier
}
`;

class ProcessEventWatcher extends EventEmitter {
  constructor() {
    super();
    this.child = null;
    this.active = false;
    this.buffer = '';
  }

  start() {
    if (this.child) return;
    let child;
    try {
      child = spawnPowerShell(PS_SCRIPT.replace(/\r?\n/g, '\n'));
    } catch (err) {
      this.emit('unavailable', err.message);
      return;
    }
    this.child = child;

    child.stdout.setEncoding('utf8');
    child.stdout.on('data', (chunk) => {
      this.buffer += chunk;
      const lines = this.buffer.split(/\r?\n/);
      this.buffer = lines.pop(); // keep any partial line for the next chunk
      lines.forEach((line) => this._handleLine(line.trim()));
    });

    child.stderr.setEncoding('utf8');
    child.stderr.on('data', (msg) => {
      if (!this.active) this.emit('unavailable', msg.trim().slice(0, 300));
    });

    child.on('exit', (code) => {
      const wasActive = this.active;
      this.child = null;
      this.active = false;
      this.buffer = '';
      if (wasActive) this.emit('stopped', code);
    });

    child.on('error', (err) => {
      this.child = null;
      this.active = false;
      this.emit('unavailable', err.message);
    });
  }

  _handleLine(line) {
    if (!line) return;
    let obj;
    try {
      obj = JSON.parse(line);
    } catch {
      return; // ignore non-JSON noise from the shell
    }
    if (obj.fatal) {
      this.emit('unavailable', obj.fatal);
      return;
    }
    if (obj.ready) {
      this.active = true;
      this.emit('ready');
      return;
    }
    if (obj.name) this.emit('process-start', obj);
  }

  stop() {
    this.active = false;
    if (this.child) {
      try {
        this.child.kill();
      } catch {
        // Already gone.
      }
      this.child = null;
    }
  }

  isActive() {
    return this.active;
  }
}

module.exports = new ProcessEventWatcher();
