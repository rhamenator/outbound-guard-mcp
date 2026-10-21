// Development-only official SDK probe; never included in the distributed server.
import assert from 'node:assert/strict';
import { once } from 'node:events';
import { createInterface } from 'node:readline';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js';

const input = createInterface({ input: process.stdin });
const client = new Client({ name: 'outbound-guard-abort-probe', version: '1' });
const transport = new StdioClientTransport({
  command: process.argv[2],
  env: { ...process.env, OUTBOUND_GUARD_ALLOWED_HOSTS: 'allowed.test' },
  stderr: 'pipe',
});
let stderr = '';
transport.stderr?.on('data', chunk => { stderr += chunk.toString(); });
try {
  await client.connect(transport);
  const controller = new AbortController();
  // Attach rejection handling immediately: abort must reject locally, then the
  // ping barrier proves that the server processed the SDK's wire cancellation.
  const pending = client.callTool({ name: 'guarded_fetch', arguments: {
    url: 'http://allowed.test/cancel-drip',
  } }, undefined, { signal: controller.signal, timeout: 15000 }).then(
    () => { throw new Error('cancelled call unexpectedly resolved'); },
    error => { assert.equal(controller.signal.aborted, true); assert.ok(error); },
  );
  console.log('FETCH_STARTED');
  assert.equal((await once(input, 'line'))[0], 'abort');
  controller.abort(new Error('synthetic-sdk-abort'));
  await pending;
  await client.ping({ timeout: 6000 });
  const resource = await client.readResource({ uri: 'outbound-guard://logs/audit.json' });
  const audit = JSON.parse(resource.contents[0].text);
  assert.deepEqual(audit.events.map(event => event.rule), ['EGRESS_CANCELLED']);
  const recovered = await client.callTool({ name: 'guarded_fetch', arguments: {
    url: 'http://allowed.test/plain',
  } });
  assert.equal(recovered.structuredContent.rule, 'EGRESS_ALLOWED');
  assert.equal(recovered.structuredContent.body_text, 'fixture-ok');
  console.log('CANCELLED_AND_RECOVERED');
  // Parent checks peer socket closure while this SDK and server are still live.
  assert.equal((await once(input, 'line'))[0], 'finish');
} finally {
  await client.close();
  input.close();
}
assert.equal(stderr, '');
