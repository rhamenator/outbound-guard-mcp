// Development-only official SDK probe; never included in the distributed server.
import { AjvJsonSchemaValidator } from '@modelcontextprotocol/client/validators/ajv';
import { Client } from '@modelcontextprotocol/client';
import { StdioClientTransport } from '@modelcontextprotocol/client/stdio';

import { runAbortProbe } from './abort_common.mjs';
const client = new Client({ name: 'outbound-guard-abort-probe', version: '2' }, {versionNegotiation:{mode:{pin:'2026-07-28'}}});
const transport = new StdioClientTransport({command:process.argv[2],
  env:{...process.env,OUTBOUND_GUARD_ALLOWED_HOSTS:'allowed.test'},stderr:'pipe'});
await runAbortProbe(client, transport, new AjvJsonSchemaValidator(), (args, options) => client.callTool(args, options), () => client.listTools(), '2026-07-28');
