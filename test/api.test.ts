/**
 * Runs the API suite against a real `wrangler dev` (workerd + Miniflare, SQLite Durable Objects) with the shipped
 * wrangler.toml defaults (the configuration "Deploy to Cloudflare" uses).
 * Set RELAY_URL to test an already running/deployed relay instead.
 */
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { spawn, ChildProcess } from 'node:child_process';
import { relayV2Suite } from './v2.suite';

const procs: ChildProcess[] = [];
let base = process.env.RELAY_URL ?? '';

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
    try { if ((await fetch(url + '/v2/health')).ok) break; } catch { /* not up yet */ }
    if (Date.now() > end || proc.exitCode !== null) throw new Error('wrangler dev did not start:\n' + log);
    await new Promise((r) => setTimeout(r, 500));
  }
  return url;
}

beforeAll(async () => {
  if (base) return;
  base = await start([]);
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

relayV2Suite('cloudflare (wrangler dev, shipped wrangler.toml defaults)', () => base);

describe('shipped template defaults', () => {
  it('health shows the relay version, protocol 2 only, and the Cloudflare implementation', async () => {
    expect(await (await fetch(`${base}/v2/health`)).json()).toMatchObject({ ok: true, service: 'paulian-sync-relay', relayVersion: '1.2.0', protocol: 2, versions: [2], impl: 'cloudflare-worker' });
  });
});
