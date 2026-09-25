// SPDX-License-Identifier: Apache-2.0
// Run: node --test test/kernel-loader.test.mjs (Node 22, built-ins only).
import assert from 'node:assert/strict';
import { test } from 'node:test';

let instance = 0;
const freshKernel = () => import(new URL(`../kernel.js?loader-test=${++instance}`, import.meta.url));
const bytes = new Uint8Array([0, 97, 115, 109, 1, 0, 0, 0]);
const response = () => ({ ok: true, status: 200, arrayBuffer: async () => bytes.slice().buffer });
function browser(t, fetch, SealModule = async () => ({})) {
  t.mock.method(globalThis, 'fetch', fetch);
  const previous = Object.getOwnPropertyDescriptor(globalThis, 'window');
  globalThis.window = { SealModule };
  t.after(() => {
    if (previous) Object.defineProperty(globalThis, 'window', previous);
    else delete globalThis.window;
  });
}

test('HTTP 200 non-wasm body is rejected, then a real wasm fetch initializes once', async (t) => {
  const html = new TextEncoder().encode('<html>bad gateway</html>');
  let fetches = 0, inits = 0;
  browser(t, async () => {
    const body = ++fetches === 1 ? html : bytes;
    return { ok: true, status: 200, arrayBuffer: async () => body.slice().buffer };
  }, async ({ wasmBinary }) => {
    inits++;
    assert.deepEqual(wasmBinary, bytes);
    return {};
  });
  const K = await freshKernel();
  await assert.rejects(K.ready(), /invalid kernel wasm header/);
  assert.equal(inits, 0);
  assert.equal(await K.ready(), true);
  assert.equal(fetches, 2);
  assert.equal(inits, 1);
  assert.deepEqual(await K.kernelBytes(), bytes);
  assert.equal(await K.ready(), true);
  assert.equal(fetches, 2);
  assert.equal(inits, 1);
});

for (const status of [404, 500]) {
  test(`#13: HTTP ${status} rejects without reading the body, then retries`, async (t) => {
    let calls = 0, reads = 0;
    browser(t, async () => ++calls === 1
      ? { ok: false, status, arrayBuffer: async () => { reads++; return bytes.buffer; } }
      : response());
    const K = await freshKernel();
    const first = K.kernelBytes();
    assert.equal(K.kernelBytes(), first);
    await assert.rejects(first, new RegExp(String(status)));
    assert.equal(reads, 0);
    const retry = K.kernelBytes();
    assert.notEqual(retry, first);
    assert.deepEqual(await retry, bytes);
    assert.equal(calls, 2);
    assert.equal(K.kernelBytes(), retry);
  });
}

for (const stage of ['fetch', 'body']) {
  test(`#14: ${stage} rejection is shared, then a fresh attempt succeeds`, async (t) => {
    const failure = new Error(`transient ${stage}`);
    let calls = 0;
    browser(t, async () => {
      if (++calls !== 1) return response();
      if (stage === 'fetch') throw failure;
      return { ok: true, arrayBuffer: async () => { throw failure; } };
    });
    const K = await freshKernel();
    const first = K.kernelBytes(), concurrent = K.kernelBytes();
    assert.equal(first, concurrent);
    const results = await Promise.allSettled([first, concurrent]);
    assert.ok(results.every(r => r.status === 'rejected' && r.reason === failure));
    const retry = K.kernelBytes();
    assert.notEqual(retry, first, 'a recovered fetch must not receive the cached rejected promise');
    assert.deepEqual(await retry, bytes);
    assert.equal(calls, 2);
  });
}

for (const stage of ['missing factory', 'sync init', 'async init', 'fetch']) {
  test(`#15: ${stage} failure reaches concurrent callers and ready retries`, async (t) => {
    const failure = new Error(`transient ${stage}`);
    let fetches = 0, inits = 0;
    browser(t, async () => {
      if (++fetches === 1 && stage === 'fetch') throw failure;
      return response();
    }, stage === 'missing factory' ? undefined : () => {
      inits++;
      if (stage === 'sync init') throw failure;
      return Promise.reject(failure);
    });
    // Passing undefined selects browser()'s default; explicitly remove it here.
    if (stage === 'missing factory') delete window.SealModule;
    const K = await freshKernel();
    const results = await Promise.allSettled([K.ready(), K.ready()]);
    assert.ok(results.every(r => r.status === 'rejected'));
    assert.equal(results[0].reason, results[1].reason);
    if (stage !== 'missing factory') assert.equal(results[0].reason, failure);
    assert.equal(inits, stage.endsWith('init') ? 1 : 0);
    let recoveredInits = 0;
    window.SealModule = async ({ wasmBinary }) => {
      recoveredInits++;
      assert.deepEqual(wasmBinary, bytes);
      wasmBinary[0] = 255; // The factory must receive a copy.
      return {};
    };
    assert.deepEqual(await Promise.all([K.ready(), K.ready()]), [true, true]);
    assert.equal(recoveredInits, 1);
    assert.equal(fetches, stage === 'fetch' ? 2 : 1);
    assert.deepEqual(await K.kernelBytes(), bytes);
    assert.equal(await K.ready(), true);
    assert.equal(recoveredInits, 1);
  });
}

test('successful in-flight fetch and init stay shared, including verification', async (t) => {
  let resolveFetch, resolveInit, fetches = 0, inits = 0;
  browser(t, () => { fetches++; return new Promise(resolve => { resolveFetch = resolve; }); },
    () => { inits++; return new Promise(resolve => { resolveInit = resolve; }); });
  const K = await freshKernel();
  const first = K.kernelBytes();
  assert.equal(K.kernelBytes(), first);
  const ready = [K.ready(), K.ready()];
  const sha = K.verifyKernelSha();
  assert.equal(fetches, 1);
  resolveFetch(response());
  await first;
  // Let the module continuation start the factory.
  await Promise.resolve();
  assert.equal(inits, 1);
  resolveInit({});
  await Promise.all(ready);
  assert.equal((await sha).computed, K.sha256Hex(bytes));
  assert.equal(K.kernelBytes(), first);
  await K.ready();
  assert.equal(fetches, 1);
  assert.equal(inits, 1);
});
