/**
 * Relay API conformance suite, protocol v2 (authenticated reads). Shared by relay/ and relay-selfhost/
 * (relay-selfhost/test/v2.suite.ts is a vendored copy). Runs against a live server URL.
 */
import { beforeAll, describe, expect, it } from 'vitest';
import WebSocket from 'ws';
import { randomBytes } from 'node:crypto';
import { LogType } from '../src/proto2';
import { Dev, Grp, authHeader, b64u, call, commit, envelope, logEntry, newDev, newGrp, ready, sha } from './helpers2';
import { hex, b64uEncode } from '../src/proto2';

export function relayV2Suite(name: string, getBase: () => string) {
  describe(`relay v2: ${name}`, () => {
    let base = '';
    beforeAll(async () => { await ready(); base = getBase(); });
    const gp = (g: Grp, sub = '') => `/v2/g/${g.gidHex}${sub}`;
    const create = async () => {
      const { g, founder } = newGrp();
      const e = logEntry(g, founder, LogType.Genesis, [founder]);
      const r = await call(base, founder, 'POST', gp(g, '/log'), { body: { entry: b64u(e) } });
      expect(r.status).toBe(200);
      commit(g, e, [founder]);
      return { g, founder };
    };
    const addMember = async (g: Grp, signer: Dev, add: Dev[]) => {
      const members = [...g.members, ...add];
      const e = logEntry(g, signer, LogType.Add, members);
      const r = await call(base, signer, 'POST', gp(g, '/log'), { body: { entry: b64u(e) } });
      if (r.status === 200) commit(g, e, members);
      return r;
    };
    const push = (g: Grp, d: Dev, blobs: Uint8Array[]) => call(base, d, 'POST', gp(g, '/changes'), { body: { changes: blobs.map(b64u) } });
    const pull = (g: Grp, d: Dev, since = 0) => call(base, d, 'GET', gp(g, '/changes'), { search: `?limit=200&since=${since}` });

    it('health reports protocol 2', async () => {
      const r = await fetch(base + '/v2/health');
      expect(await r.json()).toMatchObject({ ok: true, protocol: 2 });
    });

    it('health carries the Paulian relay signature the apps check, on /v2/health and /', async () => {
      for (const p of ['/v2/health', '/']) {
        const j = await (await fetch(base + p)).json() as Record<string, unknown>;
        expect(j.service).toBe('paulian-sync-relay');
        expect(j.protocol).toBe(2);
        expect(j.versions).toEqual([2]);
        expect(j.relayVersion).toMatch(/^\d+\.\d+\.\d+$/);
        expect(typeof j.impl).toBe('string');
        expect('v1' in j).toBe(false);
      }
    });

    it('the old protocol (v1) is gone: its paths are plain 404s', async () => {
      const gid = 'a'.repeat(64);
      expect((await fetch(base + '/v1/health')).status).toBe(404);
      expect((await fetch(`${base}/v1/groups/${gid}/changes?since=0`)).status).toBe(404);
      expect((await fetch(`${base}/v1/groups/${gid}/changes`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: '{}' })).status).toBe(404);
    });

    it('creates a group, pushes, and reads with signed requests', async () => {
      const { g, founder } = await create();
      const blobs = [envelope(g, founder), envelope(g, founder)];
      const r = await push(g, founder, blobs);
      expect(r.status).toBe(200);
      expect(r.json.results).toHaveLength(2);
      const p = await pull(g, founder);
      expect(p.status).toBe(200);
      expect(p.json.changes.map((c: any) => c.blob)).toEqual(blobs.map(b64u));
      expect(p.json.epoch).toBe(0);
      expect(p.json.head).toBe(hex(g.head));
    });

    it('rejects unauthenticated reads and writes, for existing and unknown groups alike (no existence oracle)', async () => {
      const { g, founder } = await create();
      await push(g, founder, [envelope(g, founder)]);
      const a = await call(base, null, 'GET', gp(g, '/changes'), { search: '?since=0' });
      expect(a.status).toBe(401);
      const unknown = newGrp().g;
      const b = await call(base, null, 'GET', gp(unknown, '/changes'), { search: '?since=0' });
      expect(b.status).toBe(401);
      expect(b.json).toEqual(a.json);
      const w = await call(base, null, 'POST', gp(g, '/changes'), { body: { changes: [b64u(envelope(g, founder))] } });
      expect(w.status).toBe(401);
      const l = await call(base, null, 'GET', gp(g, '/log'));
      expect(l.status).toBe(401);
      const d = await call(base, null, 'DELETE', gp(g));
      expect(d.status).toBe(401);
      // a signed request by a non-member of an existing group looks the same
      const stranger = newDev(g.gid);
      const s = await pull(g, stranger);
      expect(s.status).toBe(401);
      expect(s.json).toEqual(a.json);
    });

    it('binds the signature to method, path, query and body', async () => {
      const { g, founder } = await create();
      const blobs = [b64u(envelope(g, founder))];
      const bodyA = new TextEncoder().encode(JSON.stringify({ changes: blobs }));
      const hdr = authHeader(founder, 'POST', gp(g, '/changes'), '', bodyA);
      // tampered body
      const bodyB = new TextEncoder().encode(JSON.stringify({ changes: [b64u(envelope(g, founder))] }));
      expect((await call(base, null, 'POST', gp(g, '/changes'), { raw: bodyB, hdr })).status).toBe(401);
      // same signature on a different query
      const h2 = authHeader(founder, 'GET', gp(g, '/changes'), '?since=0');
      expect((await call(base, null, 'GET', gp(g, '/changes'), { search: '?since=1', hdr: h2 })).status).toBe(401);
      // method swap
      const h3 = authHeader(founder, 'GET', gp(g, '/log'), '');
      expect((await call(base, null, 'DELETE', gp(g, '/log'), { hdr: h3 })).status).toBe(401);
      // the untampered request works
      expect((await call(base, null, 'POST', gp(g, '/changes'), { raw: bodyA, hdr })).status).toBe(200);
    });

    it('rejects replayed requests, stale timestamps and future timestamps', async () => {
      const { g, founder } = await create();
      const hdr = authHeader(founder, 'GET', gp(g, '/log'), '');
      expect((await call(base, null, 'GET', gp(g, '/log'), { hdr })).status).toBe(200);
      const again = await call(base, null, 'GET', gp(g, '/log'), { hdr });
      expect(again.status).toBe(401);
      expect(again.json.error).toBe('replayed_request');
      const old = authHeader(founder, 'GET', gp(g, '/log'), '', new Uint8Array(0), { t: Date.now() - 6 * 60_000 });
      expect((await call(base, null, 'GET', gp(g, '/log'), { hdr: old })).json.error).toBe('stale_timestamp');
      const fut = authHeader(founder, 'GET', gp(g, '/log'), '', new Uint8Array(0), { t: Date.now() + 6 * 60_000 });
      expect((await call(base, null, 'GET', gp(g, '/log'), { hdr: fut })).json.error).toBe('stale_timestamp');
    });

    it('adds a member, who can then read; a removed member is locked out immediately', async () => {
      const { g, founder } = await create();
      await push(g, founder, [envelope(g, founder)]);
      const b = newDev(g.gid);
      expect((await pull(g, b)).status).toBe(401);
      expect((await addMember(g, founder, [b])).status).toBe(200);
      expect((await pull(g, b)).status).toBe(200);
      // b pushes in the new epoch (1)
      expect((await push(g, b, [envelope(g, b)])).status).toBe(200);
      // remove b
      const members = [founder];
      const e = logEntry(g, founder, LogType.Remove, members);
      expect((await call(base, founder, 'POST', gp(g, '/log'), { body: { entry: b64u(e) } })).status).toBe(200);
      commit(g, e, members);
      expect((await pull(g, b)).status).toBe(401);
      expect((await push(g, b, [envelope(g, b, { epoch: 2 })])).status).toBe(401);
      expect((await pull(g, founder)).status).toBe(200);
    });

    it('seeds a relay that has never seen the group with the whole verified log, by any current member', async () => {
      const { g, founder } = newGrp();
      const b = newDev(g.gid);
      const mallory = newDev(g.gid);
      const e0 = logEntry(g, founder, LogType.Genesis, [founder]); commit(g, e0, [founder]);
      const bad = logEntry(g, founder, LogType.Add, [founder, b], { badSig: true });
      const e1 = logEntry(g, founder, LogType.Add, [founder, b]); commit(g, e1, [founder, b]);
      const seed = (d: Dev, es: Uint8Array[]) => call(base, d, 'POST', gp(g, '/log'), { body: { entries: es.map(b64u) } });
      expect((await seed(mallory, [e0, e1])).status).toBe(401); // not a member of the final state
      expect((await seed(b, [e1])).status).toBe(409); // does not start at the relay's length (0)
      expect((await seed(b, [e0, bad])).json.error).toBe('bad_signature');
      expect((await pull(g, b)).status).toBe(401); // nothing was stored by the failed attempts
      const ok = await seed(b, [e0, e1]);
      expect(ok.status).toBe(200);
      expect(ok.json).toMatchObject({ length: 2 });
      expect((await pull(g, b)).status).toBe(200);
      expect((await pull(g, founder)).status).toBe(200);
      expect((await pull(g, mallory)).status).toBe(401);
      expect((await seed(b, [e0, e1])).status).toBe(409); // already there
    });

    it('validates membership entries (bad signature, wrong signer, fork, bad rules)', async () => {
      const { g, founder } = await create();
      const b = newDev(g.gid);
      const bad = logEntry(g, founder, LogType.Add, [founder, b], { badSig: true });
      expect((await call(base, founder, 'POST', gp(g, '/log'), { body: { entry: b64u(bad) } })).json.error).toBe('bad_signature');
      // stranger cannot sign an add
      const mallory = newDev(g.gid);
      const e2 = logEntry(g, mallory, LogType.Add, [founder, mallory, b]);
      expect((await call(base, mallory, 'POST', gp(g, '/log'), { body: { entry: b64u(e2) } })).status).toBe(401);
      // signer header != entry signer
      const e3 = logEntry(g, founder, LogType.Add, [founder, b]);
      const other = newDev(g.gid);
      expect((await call(base, other, 'POST', gp(g, '/log'), { body: { entry: b64u(e3) } })).status).toBe(401);
      // "add" that removes someone is rejected
      expect((await addMember(g, founder, [b])).status).toBe(200);
      const wrong = logEntry(g, founder, LogType.Add, [founder]);
      expect((await call(base, founder, 'POST', gp(g, '/log'), { body: { entry: b64u(wrong) } })).json.error).toBe('bad_add');
      // stale/forked entry (wrong index/prev) -> 409 with the current length
      const stale = { ...g, length: 1, head: sha(g.entries[0]) } as Grp;
      const e4 = logEntry(stale, founder, LogType.Rotate, [founder, b]);
      const r4 = await call(base, founder, 'POST', gp(g, '/log'), { body: { entry: b64u(e4) } });
      expect(r4.status).toBe(409);
      expect(r4.json).toMatchObject({ error: 'log_conflict', length: 2 });
      // missing key package for b
      const e5 = logEntry(g, founder, LogType.Rotate, [founder, b], { pkgFor: [] });
      expect((await call(base, founder, 'POST', gp(g, '/log'), { body: { entry: b64u(e5) } })).json.error).toBe('bad_packages');
    });

    it('cannot recreate an existing group with a second genesis', async () => {
      const { g, founder } = await create();
      const evil = newDev(g.gid);
      const g2 = { ...g, entries: [], head: new Uint8Array(32), length: 0, members: [evil] } as Grp;
      const e = logEntry(g2, evil, LogType.Genesis, [evil]);
      const r = await call(base, evil, 'POST', gp(g, '/log'), { body: { entry: b64u(e) } });
      expect(r.status).toBe(401);
      expect((await pull(g, founder)).status).toBe(200);
    });

    it('enforces envelope rules: bucket size, device, epoch, signature, duplicates', async () => {
      const { g, founder } = await create();
      const b = newDev(g.gid);
      await addMember(g, founder, [b]);
      // non-bucket size
      const odd = envelope(g, founder, { bucket: 4096 }).slice(0, 4000);
      expect((await push(g, founder, [odd])).json.error).toBe('bad_envelope');
      // bigger bucket ok, 1 MiB ok, 2 MiB too big
      expect((await push(g, founder, [envelope(g, founder, { bucket: 8192 })])).status).toBe(200);
      // someone else's device id
      expect((await push(g, founder, [envelope(g, b)])).json.error).toBe('device_mismatch');
      // stale epoch
      const st = await push(g, founder, [envelope(g, founder, { epoch: 0 })]);
      expect(st.status).toBe(409);
      expect(st.json).toMatchObject({ error: 'stale_epoch', epoch: 1 });
      // bad signature
      expect((await push(g, founder, [envelope(g, founder, { badSig: true })])).json.error).toBe('bad_signature');
      // duplicate (device, epoch, index) is idempotent
      const e = envelope(g, founder, { index: 50 });
      const first = await push(g, founder, [e]);
      const dup = await push(g, founder, [envelope(g, founder, { index: 50 })]);
      expect(first.json.results[0].duplicate).toBeUndefined();
      expect(dup.json.results[0].duplicate).toBe(true);
    });

    it('exposes only coarse metadata: stored changes have no timestamp field, sizes are bucketed', async () => {
      const { g, founder } = await create();
      await push(g, founder, [envelope(g, founder, { bucket: 4096 }), envelope(g, founder, { bucket: 16384 })]);
      const p = await pull(g, founder);
      expect(p.json.changes.map((c: any) => Buffer.from(c.blob, 'base64url').length)).toEqual([4096, 16384]);
      expect(Object.keys(p.json.changes[0]).sort()).toEqual(['blob', 'seq']);
    });

    it('compaction requires a newer snapshot and a member signature; delete needs membership', async () => {
      const { g, founder } = await create();
      const r = await push(g, founder, [envelope(g, founder), envelope(g, founder)]);
      const upto = r.json.results[1].seq;
      const noSnap = await call(base, founder, 'POST', gp(g, '/compact'), { body: { upto } });
      expect(noSnap.status).toBe(409);
      const snap = await push(g, founder, [envelope(g, founder, { kind: 2 })]);
      expect(snap.status).toBe(200);
      const ok = await call(base, founder, 'POST', gp(g, '/compact'), { body: { upto } });
      expect(ok.json.deleted).toBe(2);
      const stranger = newDev(g.gid);
      expect((await call(base, stranger, 'DELETE', gp(g))).status).toBe(401);
      expect((await call(base, founder, 'DELETE', gp(g))).json.deleted).toBe(true);
      expect((await pull(g, founder)).status).toBe(401);
    });

    it('websocket: nothing is sent before a valid signed auth frame; non-members are closed', async () => {
      const { g, founder } = await create();
      await push(g, founder, [envelope(g, founder)]);
      const wsUrl = base.replace('http', 'ws') + gp(g, '/ws') + '?since=0';
      // unauthenticated socket gets no data
      const frames: string[] = [];
      const ws = new WebSocket(wsUrl);
      await new Promise<void>((res) => ws.on('open', () => res()));
      ws.on('message', (m) => frames.push(String(m)));
      await new Promise((r) => setTimeout(r, 400));
      expect(frames).toEqual([]);
      ws.close();
      // authenticated
      const authFrame = (d: Dev) => {
        const h = authHeader(d, 'WS', `/v2/g/${g.gidHex}/ws`, '?since=0', new Uint8Array(0));
        const m = /d=([0-9a-f]+),t=(\d+),n=([^,]+),s=(.+)$/.exec(h)!;
        return JSON.stringify({ type: 'auth', d: m[1], t: Number(m[2]), n: m[3], s: m[4] });
      };
      const ws2 = new WebSocket(wsUrl);
      const got: any[] = [];
      await new Promise<void>((res) => ws2.on('open', () => res()));
      ws2.on('message', (m) => got.push(JSON.parse(String(m))));
      ws2.send(authFrame(founder));
      await new Promise((r) => setTimeout(r, 600));
      expect(got.map((x) => x.type)).toEqual(['changes', 'ready']);
      // live push is delivered
      await push(g, founder, [envelope(g, founder)]);
      await new Promise((r) => setTimeout(r, 400));
      expect(got.filter((x) => x.type === 'changes')).toHaveLength(2);
      // removal closes the socket
      const b = newDev(g.gid);
      await addMember(g, founder, [b]);
      const closed = new Promise<number>((res) => ws2.on('close', (c) => res(c)));
      const e = logEntry(g, founder, LogType.Remove, [founder]);
      // founder remains; remove b only affects b's sockets, so founder's stays open
      await call(base, founder, 'POST', gp(g, '/log'), { body: { entry: b64u(e) } });
      commit(g, e, [founder]);
      const outcome = await Promise.race([closed, new Promise<string>((r) => setTimeout(() => r('open'), 500))]);
      expect(outcome).toBe('open');
      ws2.close();
      // a non-member's auth frame closes the socket
      const ws3 = new WebSocket(wsUrl);
      await new Promise<void>((res) => ws3.on('open', () => res()));
      const code = new Promise<number>((res) => ws3.on('close', (c) => res(c)));
      ws3.send(authFrame(b));
      expect(await code).toBe(4401);
    });

    it('pairing mailbox: write-once slots, 128-bit ids only, ciphertext size bounds', async () => {
      const pid = hex(randomBytes(16));
      const put = (slot: string, blob: Uint8Array) => fetch(`${base}/v2/pair/${pid}/${slot}`, { method: 'PUT', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ blob: b64uEncode(blob) }) });
      expect((await fetch(`${base}/v2/pair/${pid}/offer`)).status).toBe(404);
      expect((await put('offer', randomBytes(100))).status).toBe(200);
      expect((await put('offer', randomBytes(100))).status).toBe(409);
      expect((await put('join', randomBytes(4))).status).toBe(400);
      expect((await put('join', randomBytes(5000))).status).toBe(413);
      expect((await put('bogus', randomBytes(100))).status).toBe(404);
      const got = await (await fetch(`${base}/v2/pair/${pid}/offer`)).json() as any;
      expect(got.blob.length).toBeGreaterThan(100);
      expect((await fetch(`${base}/v2/pair/short/offer`)).status).toBe(400);
    });
  });
}
