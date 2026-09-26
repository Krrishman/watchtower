const net = require('net');
const os = require('os');
const path = require('path');
const { EventEmitter } = require('events');

const PIPE_NAME = 'Watchtower.v1';

function defaultPipePath() {
  if (process.env.WATCHTOWER_PIPE) return process.env.WATCHTOWER_PIPE;
  // On non-Windows dev machines .NET maps named pipes to a Unix socket in the temp dir.
  return process.platform === 'win32' ? `\\\\.\\pipe\\${PIPE_NAME}` : path.join(os.tmpdir(), `CoreFxPipe_${PIPE_NAME}`);
}

class RpcError extends Error {
  constructor(code, message) {
    super(message);
    this.code = code;
  }
}

/**
 * Talks to the Watchtower service over its named pipe: newline-delimited JSON
 * requests/responses plus pushed events. Reconnects with backoff forever, because
 * the service restarting (update, crash recovery) is normal and the UI must follow it.
 */
class ServiceClient extends EventEmitter {
  constructor({ pipePath = defaultPipePath(), requestTimeoutMs = 60_000, maxLineBytes = 64 * 1024 * 1024 } = {}) {
    super();
    this.pipePath = pipePath;
    this.requestTimeoutMs = requestTimeoutMs;
    this.maxLineBytes = maxLineBytes;
    this.socket = null;
    this.connected = false;
    this.nextId = 1;
    this.pending = new Map();
    this.buffer = '';
    this.stopped = false;
    this.backoffMs = 500;
    this.retryTimer = null;
  }

  start() {
    this.stopped = false;
    this.connect();
  }

  stop() {
    this.stopped = true;
    clearTimeout(this.retryTimer);
    if (this.socket) this.socket.destroy();
  }

  connect() {
    if (this.stopped) return;
    const socket = net.connect(this.pipePath);
    this.socket = socket;
    socket.setEncoding('utf8');

    socket.on('connect', () => {
      this.connected = true;
      this.backoffMs = 500;
      this.emit('connected');
    });
    socket.on('data', (chunk) => this.onData(chunk));
    socket.on('error', () => {});
    socket.on('close', () => {
      const was = this.connected;
      this.connected = false;
      this.buffer = '';
      this.failPending(new RpcError('offline', 'The Watchtower service is not reachable.'));
      if (was) this.emit('disconnected');
      if (!this.stopped) {
        this.retryTimer = setTimeout(() => this.connect(), this.backoffMs);
        this.backoffMs = Math.min(this.backoffMs * 2, 10_000);
      }
    });
  }

  onData(chunk) {
    this.buffer += chunk;
    if (this.buffer.length > this.maxLineBytes) {
      this.socket.destroy();
      return;
    }
    let nl;
    while ((nl = this.buffer.indexOf('\n')) >= 0) {
      const line = this.buffer.slice(0, nl).trim();
      this.buffer = this.buffer.slice(nl + 1);
      if (line) this.onLine(line);
    }
  }

  onLine(line) {
    let msg;
    try {
      msg = JSON.parse(line);
    } catch {
      return;
    }
    if (msg.event) {
      this.emit('event', msg.event, msg.data);
      return;
    }
    const waiter = this.pending.get(msg.id);
    if (!waiter) return;
    this.pending.delete(msg.id);
    clearTimeout(waiter.timer);
    if (msg.error) waiter.reject(new RpcError(msg.error.code, msg.error.message));
    else waiter.resolve(msg.result);
  }

  request(method, params) {
    if (!this.connected) {
      return Promise.reject(new RpcError('offline', 'The Watchtower service is not running, so this can\'t be done right now.'));
    }
    const id = this.nextId++;
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        this.pending.delete(id);
        reject(new RpcError('timeout', 'The Watchtower service took too long to answer.'));
      }, this.requestTimeoutMs);
      this.pending.set(id, { resolve, reject, timer });
      this.socket.write(JSON.stringify({ id, method, params: params ?? {} }) + '\n');
    });
  }

  failPending(err) {
    for (const [, waiter] of this.pending) {
      clearTimeout(waiter.timer);
      waiter.reject(err);
    }
    this.pending.clear();
  }
}

module.exports = { ServiceClient, RpcError, defaultPipePath };
