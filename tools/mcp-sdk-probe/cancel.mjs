// Development-only official SDK probe; never included in the distributed server.
import { AjvJsonSchemaValidator } from '@modelcontextprotocol/sdk/validation/ajv';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js';

import { runAbortProbe } from './abort_common.mjs';
const client = new Client({ name: 'outbound-guard-abort-probe', version: '1' });
const transport = new StdioClientTransport({command:process.argv[2],
  env:{...process.env,OUTBOUND_GUARD_ALLOWED_HOSTS:'allowed.test'},stderr:'pipe'});
await runAbortProbe(client, transport, new AjvJsonSchemaValidator(), (args, options) => client.callTool(args, undefined, options), () => client.ping({timeout:6000}));
