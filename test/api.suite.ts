/**
 * Relay API conformance suite (protocol v1). Shared by relay/ and relay-selfhost/
 * (relay-selfhost/test/api.suite.ts is a vendored copy). Runs against a live server URL.
 */
import { describe, expect, it, beforeAll } from 'vitest';
import sodium from 'libsodium-wrappers-sumo';
import WebSocket from 'ws';
import { createHash, randomBytes } from 'node:crypto';

const b64u = (b: Uint8Array) => Buffer.from(b).toString('base64url');

export interface Group { gid: string; pk: Uint8Array; sk: Uint8Array; counter: number; device: Uint8Array }

export function newGroup(): Group {
  const kp = sodium.crypto_sign_seed_keypair(randomBytes(32));
  const gid = createHash('sha256').update(Buffer.from('paulian-sync/v1/group-id')).update(kp.publicKey).digest('hex');
  return { gid, pk: kp.publicKey, sk: kp.privateKey, counter: 0, device: randomBytes(16) };
}

export function envelope(g: Group, opts: { counter?: number; ctBytes?: number; kind?: number } = {}): Uint8Array {
  const counter = opts.counter ?? ++g.counter;
  const header = Buffer.alloc(38);
  header.write('PCS1', 0, 'latin1'); header[4] = 1; header[5] = opts.kind ?? 1;
  Buffer.from(g.device).copy(header, 6);
  header.writeBigUInt64BE(BigInt(counter), 22);
  header.writeBigUInt64BE(BigInt(Date.now()), 30);
  const body = Buffer.concat([header, randomBytes(24), randomBytes(opts.ctBytes ?? 64)]);
  const sig = sodium.crypto_sign_detached(Buffer.concat([Buffer.from('paulian-sync/v1/sig'), Buffer.from(g.gid, 'hex'), body]), g.sk);
  return Buffer.concat([body, sig]);
}

export function relayApiSuite(name: string, getBase: () => string) {
  describe(`relay API: ${name}`, () => {
    let base = '';
    beforeAll(async () => { await sodium.ready; base = getBase(); });
    const url = (g: Group, sub = '/changes') => `${base}/v1/groups/${g.gid}${sub}`;
    const push = (g: Group, blobs: Uint8Array[], pk = g.pk) => fetch(url(g), {
      method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ pk: b64u(pk), changes: blobs.map(b64u) }),
    });
    const get = (g: Group, since = 0, limit = 200) => fetch(`${url(g)}?since=${since}&limit=${limit}`);
    const signed = (g: Group, msg: string) => b64u(sodium.crypto_sign_detached(Buffer.from(msg), g.sk));

    it('health', async () => {
      const r = await fetch(`${base}/v1/health`);
      expect(r.status).toBe(200);
      expect(await r.json()).toMatchObject({ ok: true });
    });

    it('push then fetch since a cursor', async () => {
      const g = newGroup();
      const blobs = [envelope(g), envelope(g), envelope(g)];
      const r = await push(g, blobs);
      expect(r.status).toBe(200);
      const j: any = await r.json();
      expect(j.results).toHaveLength(3);
      expect(j.count).toBe(3);
      const seqs = j.results.map((x: any) => x.seq);
      expect(seqs[0]).toBeLessThan(seqs[1]);
      const all: any = await (await get(g)).json();
      expect(all.changes.map((c: any) => c.blob)).toEqual(blobs.map(b64u));
      expect(all.more).toBe(false);
      const after: any = await (await get(g, seqs[0])).json();
      expect(after.changes).toHaveLength(2);
      const page: any = await (await get(g, 0, 2)).json();
      expect(page.changes).toHaveLength(2);
      expect(page.more).toBe(true);
      expect(page.cursor).toBe(seqs[1]);
      const empty: any = await (await get(newGroup())).json();
      expect(empty).toMatchObject({ changes: [], more: false });
    });

    it('rejects replayed (device, counter) as duplicate', async () => {
      const g = newGroup();
      const b = envelope(g);
      const first: any = await (await push(g, [b])).json();
      const again: any = await (await push(g, [b])).json();
      expect(again.results[0]).toEqual({ seq: first.results[0].seq, duplicate: true });
      const same = envelope(g, { counter: 1 });
      const third: any = await (await push(g, [same])).json();
      expect(third.results[0].duplicate).toBe(true);
      expect(((await (await get(g)).json()) as any).changes).toHaveLength(1);
    });

    it('rejects injected / tampered / malformed changes', async () => {
      const g = newGroup(), h = newGroup();
      expect((await push(g, [envelope(h)], h.pk)).status).toBe(403);          // pk of another group
      expect((await push(g, [envelope(h)])).status).toBe(403);                // signed by another group
      const t = envelope(g); t[50] ^= 1;
      expect((await push(g, [t])).status).toBe(403);                          // tampered
      expect((await push(g, [randomBytes(200)])).status).toBe(400);           // not an envelope
      expect((await push(g, [envelope(g, { counter: 0 })])).status).toBe(400);
      const r = await fetch(url(g), { method: 'POST', headers: { 'content-type': 'application/json' }, body: '{nope' });
      expect(r.status).toBe(400);
      expect((await fetch(`${base}/v1/groups/NOT-A-GROUP/changes`)).status).toBe(400);
      expect(((await (await get(g)).json()) as any).changes).toHaveLength(0);
    });

    it('enforces payload caps', async () => {
      const g = newGroup();
      expect((await push(g, [envelope(g, { ctBytes: 1024 * 1024 })])).status).toBe(413);
      const many = Array.from({ length: 101 }, () => envelope(g, { ctBytes: 16 }));
      expect((await push(g, many)).status).toBe(413);
      const huge = 'x'.repeat(3 * 1024 * 1024 + 10);
      // A server that rejects an oversized body early may close the socket mid-upload; Node 24's fetch then
      // surfaces EPIPE/ECONNRESET instead of the 413. Either outcome means the body was refused.
      const status = await fetch(url(g), { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ pk: b64u(g.pk), changes: [huge] }) })
        .then((r) => r.status, (e) => { if (/EPIPE|ECONNRESET|fetch failed/.test(String(e) + String(e?.cause))) return 413; throw e; });
      expect(status).toBe(413);
    });

    it('streams backlog and live changes over WebSocket', async () => {
      const g = newGroup();
      await push(g, [envelope(g)]);
      const ws = new WebSocket(url(g, '/ws').replace(/^http/, 'ws') + '?since=0');
      const frames: any[] = [];
      ws.on('message', (d) => { const s = d.toString(); if (s !== 'pong') frames.push(JSON.parse(s)); });
      await new Promise<void>((res, rej) => { ws.once('open', () => res()); ws.once('error', rej); });
      await waitFor(() => frames.some((f) => f.type === 'ready'));
      expect(frames[0].type).toBe('changes');
      expect(frames[0].changes).toHaveLength(1);
      const live = envelope(g);
      await push(g, [live]);
      await waitFor(() => frames.filter((f) => f.type === 'changes').length >= 2);
      const last = frames.filter((f) => f.type === 'changes').pop();
      expect(last.changes[0].blob).toBe(b64u(live));
      ws.close();
    });

    it('compacts only with a valid fresh signature, keeping the newest change', async () => {
      const g = newGroup();
      const j: any = await (await push(g, [envelope(g), envelope(g), envelope(g)])).json();
      const upto = j.results[2].seq;
      const ts = Date.now();
      const bad = await fetch(url(g, '/compact'), { method: 'POST', headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ pk: b64u(g.pk), upto, ts, sig: signed(newGroup(), `paulian-sync/v1/compact:${g.gid}:${upto}:${ts}`) }) });
      expect(bad.status).toBe(403);
      const stale = await fetch(url(g, '/compact'), { method: 'POST', headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ pk: b64u(g.pk), upto, ts: ts - 3600_000, sig: signed(g, `paulian-sync/v1/compact:${g.gid}:${upto}:${ts - 3600_000}`) }) });
      expect(stale.status).toBe(400);
      const ok = await fetch(url(g, '/compact'), { method: 'POST', headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ pk: b64u(g.pk), upto, ts, sig: signed(g, `paulian-sync/v1/compact:${g.gid}:${upto}:${ts}`) }) });
      expect(ok.status).toBe(200);
      expect(((await ok.json()) as any).deleted).toBe(2);
      const left: any = await (await get(g)).json();
      expect(left.changes.map((c: any) => c.seq)).toEqual([upto]);
      // sequence numbers keep increasing after compaction
      const n: any = await (await push(g, [envelope(g)])).json();
      expect(n.results[0].seq).toBeGreaterThan(upto);
    });

    it('deletes a group only with a valid signature', async () => {
      const g = newGroup();
      await push(g, [envelope(g)]);
      const ts = Date.now();
      const bad = await fetch(url(g, ''), { method: 'DELETE', headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ pk: b64u(g.pk), ts, sig: signed(g, `paulian-sync/v1/delete:${g.gid}:${ts + 1}`) }) });
      expect(bad.status).toBe(403);
      const ok = await fetch(url(g, ''), { method: 'DELETE', headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ pk: b64u(g.pk), ts, sig: signed(g, `paulian-sync/v1/delete:${g.gid}:${ts}`) }) });
      expect(ok.status).toBe(200);
      expect(((await (await get(g)).json()) as any).changes).toHaveLength(0);
    });

    it('answers CORS preflight', async () => {
      const r = await fetch(url(newGroup()), { method: 'OPTIONS' });
      expect(r.status).toBe(204);
      expect(r.headers.get('access-control-allow-origin')).toBe('*');
    });

    it('rate limits pushes per group', async () => {
      const g = newGroup();
      let limited: Response | null = null;
      for (let i = 0; i < 80 && !limited; i++) {
        const r = await push(g, [envelope(g, { ctBytes: 16 })]);
        if (r.status === 429) limited = r;
        else expect(r.status).toBe(200);
      }
      expect(limited).not.toBeNull();
      expect(Number(limited!.headers.get('retry-after'))).toBeGreaterThan(0);
    });
  });
}

async function waitFor(fn: () => boolean, ms = 5000) {
  const end = Date.now() + ms;
  while (!fn()) {
    if (Date.now() > end) throw new Error('timeout');
    await new Promise((r) => setTimeout(r, 25));
  }
}
