const test = require('node:test');
const assert = require('node:assert');
const net = require('net');
const os = require('os');
const path = require('path');
const fs = require('fs');
const { ServiceClient } = require('../lib/serviceClient');

function pipePath() {
  const name = `wt-test-${process.pid}-${Math.random().toString(36).slice(2)}`;
  return process.platform === 'win32' ? `\\\\.\\pipe\\${name}` : path.join(os.tmpdir(), name);
}

// Minimal stand-in for the service: echoes, errors, and pushes an event on connect.
function mockService(where) {
  const server = net.createServer((socket) => {
    socket.setEncoding('utf8');
    socket.write(JSON.stringify({ event: 'alert', data: { title: 'hello' } }) + '\n');
    let buf = '';
    socket.on('data', (chunk) => {
      buf += chunk;
      let nl;
      while ((nl = buf.indexOf('\n')) >= 0) {
        const req = JSON.parse(buf.slice(0, nl));
        buf = buf.slice(nl + 1);
        if (req.method === 'fail') {
          socket.write(JSON.stringify({ id: req.id, error: { code: 'forbidden', message: 'admins only' } }) + '\n');
        } else if (req.method === 'split') {
          // Deliver one reply across two writes to prove partial lines are reassembled.
          const line = JSON.stringify({ id: req.id, result: { big: 'x'.repeat(5000) } }) + '\n';
          socket.write(line.slice(0, 100));
          setTimeout(() => socket.write(line.slice(100)), 20);
        } else if (req.method !== 'hang') {
          socket.write(JSON.stringify({ id: req.id, result: { method: req.method, params: req.params } }) + '\n');
        }
      }
    });
  });
  return new Promise((resolve) => server.listen(where, () => resolve(server)));
}

function once(emitter, name) {
  return new Promise((resolve) => emitter.once(name, (...args) => resolve(args)));
}

test('round-trips requests, errors and pushed events', async () => {
  const where = pipePath();
  const server = await mockService(where);
  const client = new ServiceClient({ pipePath: where, requestTimeoutMs: 500 });
  const event = once(client, 'event');
  client.start();
  await once(client, 'connected');

  const [name, data] = await event;
  assert.equal(name, 'alert');
  assert.equal(data.title, 'hello');

  const r = await client.request('history.get', { limit: 5 });
  assert.deepEqual(r, { method: 'history.get', params: { limit: 5 } });

  await assert.rejects(client.request('fail'), (err) => err.code === 'forbidden' && err.message === 'admins only');
  assert.equal((await client.request('split')).big.length, 5000);
  await assert.rejects(client.request('hang'), (err) => err.code === 'timeout');

  client.stop();
  server.close();
});

test('rejects immediately while offline, then reconnects when the service appears', async () => {
  const where = pipePath();
  const client = new ServiceClient({ pipePath: where });
  client.start();
  await assert.rejects(client.request('hello'), (err) => err.code === 'offline');

  const server = await mockService(where);
  await once(client, 'connected');
  assert.equal((await client.request('hello')).method, 'hello');

  // Service restarts (update / crash recovery): pending calls fail, client comes back by itself.
  const disconnected = once(client, 'disconnected');
  server.close();
  client.socket.destroy();
  await disconnected;
  const server2 = await mockService(where);
  await once(client, 'connected');
  assert.equal((await client.request('again')).method, 'again');

  client.stop();
  server2.close();
  if (process.platform !== 'win32') fs.rmSync(where, { force: true });
});
