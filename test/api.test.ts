/**
 * Runs the API suite against a real `wrangler dev` (workerd + Miniflare, SQLite Durable Objects).
 * Set RELAY_URL to test an already running/deployed relay instead.
 */
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { spawn, ChildProcess } from 'node:child_process';
import { relayApiSuite } from './api.suite';
import { relayV2Suite } from './v2.suite';

const procs: ChildProcess[] = [];
let base = process.env.RELAY_URL ?? '';
let baseDefault = '';

/** Starts a wrangler dev server. `vars` override [vars] from wrangler.toml. */
async function start(vars: string[]): Promise<string> {
  const port = 8787 + Math.floor(Math.random() * 1500);
  const proc = spawn('npx', ['wrangler', 'dev', '--port', String(port), '--ip', '127.0.0.1', '--persist-to', `.wrangler/test-state-${port}`, '--show-interactive-dev-session=false', ...vars.flatMap((v) => ['--var', v])], {
    cwd: new URL('..', import.meta.url).pathname, stdio: ['ignore', 'pipe', 'pipe'], detached: true, env: { ...process.env, WRANGLER_SEND_METRICS: 'false', CI: '1' },
  });
  procs.push(proc);
  let log = '';
  proc.stdout!.on('data', (d) => { log += d; });
  proc.stderr!.on('data', (d) => { log += d; });
  const url = `http://127.0.0.1:${port}`;
  const end = Date.now() + 90_000;
  for (;;) {
    try { if ((await fetch(url + '/v1/health')).ok) break; } catch { /* not up yet */ }
    if (Date.now() > end || proc.exitCode !== null) throw new Error('wrangler dev did not start:\n' + log);
    await new Promise((r) => setTimeout(r, 500));
  }
  return url;
}

beforeAll(async () => {
  if (base) return;
  // Instance 1: legacy v1 writes enabled so the v1 conformance suite can still run. Instance 2: shipped defaults.
  base = await start(['V1_MODE:readwrite']);
  baseDefault = await start([]);
}, 240_000);

afterAll(async () => {
  for (const proc of procs) {
    if (!proc.pid) continue;
    // kill the whole process group (npx -> wrangler -> workerd)
    try { process.kill(-proc.pid, 'SIGTERM'); } catch { /* already gone */ }
  }
  await new Promise((r) => setTimeout(r, 500));
  for (const proc of procs) { try { process.kill(-proc.pid!, 'SIGKILL'); } catch { /* already gone */ } }
});

relayApiSuite('cloudflare (wrangler dev, V1_MODE=readwrite)', () => base);
relayV2Suite('cloudflare (wrangler dev)', () => base);

describe('shipped template defaults (wrangler.toml: V1_MODE=off, the config "Deploy to Cloudflare" uses)', () => {
  it('v1 is retired (410) for a new relay, and /v1/health still answers because the apps probe it', async () => {
    const gid = 'a'.repeat(64);
    const post = await fetch(`${baseDefault}/v1/groups/${gid}/changes`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: '{}' });
    expect(post.status).toBe(410);
    expect((await fetch(`${baseDefault}/v1/groups/${gid}/changes?since=0`)).status).toBe(410);
    expect((await fetch(`${baseDefault}/v1/health`)).status).toBe(200);
  });
  it('v2 works on the default configuration and the health signature is present', async () => {
    expect(await (await fetch(`${baseDefault}/v1/health`)).json()).toMatchObject({ ok: true, service: 'paulian-sync-relay', relayVersion: '1.1.0', protocol: 2, versions: [2], v1: 'off', impl: 'cloudflare-worker' });
  });
});
