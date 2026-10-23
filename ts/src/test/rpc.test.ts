import assert from 'node:assert/strict';
import test from 'node:test';
import { chmodSync, mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import type { AnalyzeArgs } from '../engine.js';
import { RpcEngine } from '../rpc.js';

/**
 * A backend that writes the `task.start` reply and the completion in a single
 * write. Node may then deliver both lines in one read chunk, which is the
 * ordering that used to drop a fast result and leave the interface busy
 * forever: the completion was compared against a task id that only becomes
 * known from the start reply.
 */
const BACKEND = `#!/usr/bin/env node
import { writeSync } from 'node:fs';

const result = {
  plugin: 'lsmod',
  columns: ['Name', 'Base', 'Size'],
  rows: [['test', '0x0000000000009000', '4096']],
  complete: true,
  diagnostics: [],
  banner: 'Linux version test',
  symbol: 'test.json',
  page_table: 0x1000,
  historical: false,
  system: 'linux',
  kernel_identity: null,
};

let sent = false;
process.stdin.on('data', (chunk) => {
  if (sent || !chunk.toString().includes('"method":"task.start"')) {
    return;
  }
  sent = true;
  const request = JSON.parse(chunk.toString().split('\\n')[0]);
  const start = JSON.stringify({ jsonrpc: '2.0', id: request.id, result: { task: 't1' } });
  const done = JSON.stringify({ jsonrpc: '2.0', method: 'task.done', params: { id: 't1', result: { result } } });
  // One write: the client can receive both lines in the same chunk.
  writeSync(1, start + '\\n' + done + '\\n');
});
process.stdin.resume();
`;

const args: AnalyzeArgs = {
  image: 'image.raw',
  symbols: null,
  plugin: 'lsmod',
  symbol_choice: null,
  options: {},
  dump: null,
  no_cache: false,
};

test('a task that completes before its start reply still settles the request', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'zero-rpc-'));
  const backend = join(dir, 'backend.mjs');
  writeFileSync(backend, BACKEND);
  chmodSync(backend, 0o755);
  const engine = new RpcEngine(backend, dir);
  let timer: NodeJS.Timeout | undefined;
  try {
    const timeout = new Promise<never>((_, reject) => {
      timer = setTimeout(() => reject(new Error('analysis stayed busy after its result')), 2_000);
    });
    const reply = await Promise.race([engine.analyze(args, () => undefined), timeout]);
    assert.equal(engine.busy, false);
    assert.deepEqual(reply.result?.rows, [['test', '0x0000000000009000', '4096']]);
  } finally {
    clearTimeout(timer);
    await engine.close();
  }
});
