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
    try { await fetch(url + '/v2/health'); break; } catch { /* not up yet */ }
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

describe('hardening against strangers', () => {
  it('a probe of an unknown group does not stop that group from being created afterwards', async () => {
    const { b64u, call, logEntry, newGrp, ready } = await import('./helpers2');
    const { LogType } = await import('../src/proto2');
    await ready();
    const { g, founder } = newGrp();
    const probe = await call(base, null, 'GET', `/v2/g/${g.gidHex}/changes`, { search: '?since=0' });
    expect(probe.status).toBe(401);
    const e = logEntry(g, founder, LogType.Genesis, [founder]);
    const created = await call(base, founder, 'POST', `/v2/g/${g.gidHex}/log`, { body: { entry: b64u(e) } });
    expect(created.status).toBe(200);
  });
});

describe('optional access key (configured)', () => {
  const SECRET = 'test-relay-access-key-for-suite';
  let keyed = '';
  beforeAll(async () => {
    keyed = await start([`RELAY_ACCESS_SECRET:${SECRET}`]);
  }, 240_000);

  it('health without the key is the same generic 401 as an unknown group', async () => {
    const h = await fetch(keyed + '/v2/health');
    const g = await fetch(keyed + '/v2/g/' + 'ab'.repeat(32) + '/changes?since=0');
    expect(h.status).toBe(401);
    expect(g.status).toBe(401);
    expect(await h.json()).toEqual({ error: 'unauthorized' });
    expect(await g.json()).toEqual({ error: 'unauthorized' });
  });

  it('health with the key reports the Paulian signature', async () => {
    const r = await fetch(keyed + '/v2/health', { headers: { 'x-paulian-relay-key': SECRET } });
    expect(r.status).toBe(200);
    expect(await r.json()).toMatchObject({ ok: true, service: 'paulian-sync-relay', relayVersion: '1.3.0', protocol: 2, impl: 'cloudflare-worker' });
  });

  it('a group can be created only when the access key is sent; pairing stays reachable without it', async () => {
    const { b64u, call, logEntry, newGrp, ready } = await import('./helpers2');
    const { LogType, hex } = await import('../src/proto2');
    const { randomBytes } = await import('node:crypto');
    await ready();
    const { g, founder } = newGrp();
    const e = logEntry(g, founder, LogType.Genesis, [founder]);
    expect((await call(keyed, founder, 'POST', `/v2/g/${g.gidHex}/log`, { body: { entry: b64u(e) } })).status).toBe(401);
    expect((await call(keyed, founder, 'POST', `/v2/g/${g.gidHex}/log`, { body: { entry: b64u(e) }, accessKey: SECRET })).status).toBe(200);
    const pid = hex(randomBytes(16));
    // Pairing no longer answers strangers: without a pairing-secret proof the reply is the same generic 401.
    expect((await fetch(`${keyed}/v2/pair/${pid}/offer`)).status).toBe(401);
    expect((await fetch(`${keyed}/v2/health?rk=${encodeURIComponent(SECRET)}`)).status).toBe(401);
  });

  it('a WebSocket upgrade with a bad Authorization header is refused before the socket opens', async () => {
    const { b64u, call, logEntry, newGrp, ready } = await import('./helpers2');
    const { LogType } = await import('../src/proto2');
    const WebSocket = (await import('ws')).default;
    await ready();
    const { g, founder } = newGrp();
    const e = logEntry(g, founder, LogType.Genesis, [founder]);
    expect((await call(keyed, founder, 'POST', `/v2/g/${g.gidHex}/log`, { body: { entry: b64u(e) }, accessKey: SECRET })).status).toBe(200);
    const wsUrl = keyed.replace('http', 'ws') + `/v2/g/${g.gidHex}/ws?since=0`;
    expect(wsUrl).not.toContain(SECRET);
    expect(wsUrl).not.toMatch(/[?&]rk=/);
    const status = await new Promise<number>((resolve, reject) => {
      const ws = new WebSocket(wsUrl, { headers: { authorization: 'PCS2 d=00,t=1,n=x,s=y' } });
      ws.once('unexpected-response', (_req, res) => resolve(res.statusCode ?? 0));
      ws.once('open', () => { ws.close(); reject(new Error('socket opened')); });
      ws.once('error', () => resolve(-1));
    });
    expect(status === 401 || status === -1).toBe(true);
  });

  it('authenticates a WebSocket with the access key in the first frame, not the URL', async () => {
    const { authHeader, b64u, call, logEntry, newGrp, ready } = await import('./helpers2');
    const { LogType } = await import('../src/proto2');
    const WebSocket = (await import('ws')).default;
    await ready();
    const { g, founder } = newGrp();
    const e = logEntry(g, founder, LogType.Genesis, [founder]);
    expect((await call(keyed, founder, 'POST', `/v2/g/${g.gidHex}/log`, { body: { entry: b64u(e) }, accessKey: SECRET })).status).toBe(200);
    const wsUrl = keyed.replace('http', 'ws') + `/v2/g/${g.gidHex}/ws?since=0`;
    expect(wsUrl).not.toContain(SECRET);

    const frameOf = (k?: string) => {
      const h = authHeader(founder, 'WS', `/v2/g/${g.gidHex}/ws`, '?since=0', new Uint8Array(0));
      const m = /d=([0-9a-f]+),t=(\d+),n=([^,]+),s=(.+)$/.exec(h)!;
      return JSON.stringify({ type: 'auth', d: m[1], t: Number(m[2]), n: m[3], s: m[4], ...(k ? { k } : {}) });
    };

    const missed = new WebSocket(wsUrl);
    await new Promise<void>((res) => missed.on('open', () => res()));
    const missedCode = new Promise<number>((res) => missed.on('close', (c) => res(c)));
    missed.send(frameOf());
    expect(await missedCode).toBe(4401);

    const leaked = keyed.replace('http', 'ws') + `/v2/g/${g.gidHex}/ws?since=0&rk=${encodeURIComponent(SECRET)}`;
    const viaQuery = new WebSocket(leaked);
    await new Promise<void>((res) => viaQuery.on('open', () => res()));
    const viaQueryCode = new Promise<number>((res) => viaQuery.on('close', (c) => res(c)));
    viaQuery.send(frameOf());
    expect(await viaQueryCode).toBe(4401);

    const ws = new WebSocket(wsUrl);
    const got: any[] = [];
    await new Promise<void>((res) => ws.on('open', () => res()));
    ws.on('message', (m) => got.push(JSON.parse(String(m))));
    ws.send(frameOf(SECRET));
    await new Promise((r) => setTimeout(r, 600));
    expect(got.map((x) => x.type)).toContain('ready');
    ws.close();
  });

  it('pairing accepts a proof derived from the pairing secret and rejects a stranger', async () => {
    const { ready, sha } = await import('./helpers2');
    const { PAIR_AUTH_PK_HEADER, PAIR_AUTH_SIG_HEADER, PAIR_AUTH_TS_HEADER, b64uEncode, hex, pairAuthMessage, utf8 } = await import('../src/proto2');
    const { randomBytes } = await import('node:crypto');
    const sodium = (await import('libsodium-wrappers-sumo')).default;
    await ready();
    const kp = sodium.crypto_sign_seed_keypair(randomBytes(32));
    const pid = hex(randomBytes(16));
    const path = `/v2/pair/${pid}/offer`;
    const blob = b64uEncode(randomBytes(32));
    const body = JSON.stringify({ blob });
    expect((await fetch(`${keyed}${path}`, { method: 'PUT', headers: { 'content-type': 'application/json' }, body })).status).toBe(401);

    const sign = (method: string, bodyText: string, now: number) => {
      const bytes = bodyText ? utf8(bodyText) : new Uint8Array(0);
      const msg = pairAuthMessage(method, path, now, hex(sha(bytes)));
      const sig = sodium.crypto_sign_detached(msg, kp.privateKey);
      return {
        [PAIR_AUTH_TS_HEADER]: String(now),
        [PAIR_AUTH_SIG_HEADER]: b64uEncode(sig),
        [PAIR_AUTH_PK_HEADER]: b64uEncode(kp.publicKey),
      };
    };
    const now = Date.now();
    const put = await fetch(`${keyed}${path}`, { method: 'PUT', headers: { 'content-type': 'application/json', ...sign('PUT', body, now) }, body });
    expect(put.status).toBe(200);
    const got = await fetch(`${keyed}${path}`, { headers: sign('GET', '', now + 1) });
    expect(got.status).toBe(200);
    expect((await got.json() as { blob: string }).blob).toBe(blob);
    expect((await fetch(`${keyed}${path}`)).status).toBe(401);
  });
});

describe('shipped template defaults', () => {
  it('health shows the relay version, protocol 2 only, and the Cloudflare implementation', async () => {
    expect(await (await fetch(`${base}/v2/health`)).json()).toMatchObject({ ok: true, service: 'paulian-sync-relay', relayVersion: '1.3.0', protocol: 2, versions: [2], impl: 'cloudflare-worker' });
  });
});
