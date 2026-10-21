// Development-only official SDK probe; never included in the distributed server.
import assert from 'node:assert/strict';
import { once } from 'node:events';
import { createInterface } from 'node:readline';
import { AjvJsonSchemaValidator } from '@modelcontextprotocol/sdk/validation/ajv';
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
  const listed = await client.listTools();
  const schema = listed.tools.find(tool => tool.name === 'guarded_fetch').outputSchema;
  assert.equal(schema.type, 'object');
  const validate = new AjvJsonSchemaValidator().getValidator(schema);
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
  assert.equal(validate(recovered.structuredContent).valid, true);
  const blocked = await client.callTool({ name: 'guarded_fetch', arguments: {
    url: 'http://127.0.0.1/',
  } });
  assert.equal(blocked.isError, true);
  assert.equal(blocked.structuredContent.rule, 'EGRESS_INVALID_HOST');
  assert.equal(validate(blocked.structuredContent).valid, true);
  // The audit may fail before allocating an ID; that fail-closed result is valid.
  assert.equal(validate({ status: 'BLOCKED', rule: 'EGRESS_AUDIT_FAILURE',
    remediation: 'Restart the server.' }).valid, true);
  for (const bad of [
    { ...blocked.structuredContent, body_text: 'must not leak' },
    { ...blocked.structuredContent, url: 'http://secret.invalid/' },
    { ...blocked.structuredContent, rule: 'EGRESS_ALLOWED' },
    { ...recovered.structuredContent, untrusted_content: false },
    { ...recovered.structuredContent, status_code: 1000 },
    { ...recovered.structuredContent, correlation_id: 'arbitrary' },
    { ...recovered.structuredContent, body_text: null },
    { ...recovered.structuredContent, unexpected: true },
  ]) assert.equal(validate(bad).valid, false);
  const missing = { ...recovered.structuredContent };
  delete missing.body_text;
  assert.equal(validate(missing).valid, false);
  console.log('CANCELLED_AND_RECOVERED');
  // Parent checks peer socket closure while this SDK and server are still live.
  assert.equal((await once(input, 'line'))[0], 'finish');
} finally {
  await client.close();
  input.close();
}
assert.equal(stderr, '');
