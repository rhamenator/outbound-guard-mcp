// Development-only official SDK client: send the overload frames itself.
import assert from 'node:assert/strict';
import { once } from 'node:events';
import { createInterface } from 'node:readline';
import { Client } from '@modelcontextprotocol/client';
import { StdioClientTransport } from '@modelcontextprotocol/client/stdio';

const input = createInterface({ input: process.stdin });
const client = new Client({ name: 'outbound-guard-overload-probe', version: '1' },
  { versionNegotiation: { mode: { pin: '2026-07-28' } } });
const transport = new StdioClientTransport({ command: process.argv[2],
  env: { ...process.env, OUTBOUND_GUARD_ALLOWED_HOSTS: 'allowed.test' }, stderr: 'pipe' });
let stderr = '';
transport.stderr?.on('data', chunk => { stderr += chunk.toString(); });
try {
  await client.connect(transport);
  assert.equal(client.getNegotiatedProtocolVersion(), '2026-07-28');
  const cycles = 12;
  for (let cycle = 0; cycle < cycles; cycle++) {
    const controller = new AbortController();
    const held = client.callTool({ name: 'guarded_fetch', arguments: {
      url: 'http://allowed.test/cancel-drip',
    } }, { signal: controller.signal, timeout: 15000 }).then(
      () => { throw new Error('cancelled fetch unexpectedly resolved'); },
      error => { assert.ok(controller.signal.aborted && error); },
    );
    console.log('FETCH_STARTED');
    assert.equal((await once(input, 'line'))[0], 'flood');
    const padding = 'x'.repeat(60000);
    const queued = Array.from({ length: 8 }, () => client.request({
      method: 'tools/list', params: { padding },
    }).then(value => ({ ok: true, value }), error => ({ ok: false, error })));
    const busy = client.request({ method: 'tools/call', params: {
      name: 'guarded_fetch', padding, arguments: {
        url: 'http://allowed.test/SYNTHETIC_BUSY_MARKER',
      },
    } }).then(value => ({ ok: true, value }), error => ({ ok: false, error }));
    controller.abort(new Error('synthetic-sdk-overload-abort'));
    const results = await Promise.all(queued);
    const denied = await busy;
    await held;
    assert.ok(results.every(result => result.ok && result.value.tools?.length > 0), results);
    assert.equal(denied.ok, false, denied);
    assert.equal(denied.error.code, -32000);
    assert.equal(denied.error.data?.rule, 'MCP_INPUT_BUSY');
    const audit = await client.readResource({ uri: 'outbound-guard://logs/audit.json' });
    assert.deepEqual(JSON.parse(audit.contents[0].text).events.map(event => event.rule),
      Array.from({ length: cycle }, () => ['EGRESS_CANCELLED', 'EGRESS_ALLOWED'])
        .flat().concat('EGRESS_CANCELLED'));
    const recovery = await client.callTool({ name: 'guarded_fetch', arguments: {
      url: 'http://allowed.test/plain',
    } });
    assert.equal(recovery.structuredContent.rule, 'EGRESS_ALLOWED');
    assert.equal(recovery.structuredContent.body_text, 'fixture-ok');
    console.log('SDK_OVERLOAD_RECOVERED');
    if (cycle + 1 < cycles) {
      assert.equal((await once(input, 'line'))[0], 'continue');
    }
  }
  const finalAudit = await client.readResource({ uri: 'outbound-guard://logs/audit.json' });
  assert.deepEqual(JSON.parse(finalAudit.contents[0].text).events.map(event => event.rule),
    Array.from({ length: cycles }, () => ['EGRESS_CANCELLED', 'EGRESS_ALLOWED']).flat());
  console.log('SDK_OVERLOAD_AUDIT_DONE');
  assert.equal((await once(input, 'line'))[0], 'finish');
} finally {
  await client.close();
  input.close();
}
assert.equal(stderr, '');
