// Checks that an installed Watchtower service answers on its pipe (used by CI after installing the MSI).
const { ServiceClient } = require('../lib/serviceClient');

async function attempt() {
  const client = new ServiceClient();
  try {
    await new Promise((resolve, reject) => {
      client.once('connected', resolve);
      setTimeout(() => reject(new Error('could not connect to the service pipe')), 10_000);
      client.start();
    });
    const hello = await client.request('hello');
    const verify = await client.request('history.verify');
    const state = await client.request('state.get');
    console.log(JSON.stringify({ hello, verify, sensors: state.sensors }, null, 2));
    if (hello.protocol !== 1) throw new Error('unexpected protocol version');
    if (!verify.ok) throw new Error(`history does not verify: ${verify.message}`);
  } finally {
    client.stop();
  }
}

(async () => {
  for (let i = 1; i <= 5; i++) {
    try {
      await attempt();
      console.log('Service answered on its pipe.');
      process.exit(0);
    } catch (err) {
      console.error(`attempt ${i}: ${err.code || ''} ${err.message}`);
      await new Promise((r) => setTimeout(r, 3000));
    }
  }
  process.exit(1);
})();
