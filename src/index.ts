/**
 * Paulian Sync relay for Cloudflare Workers (free plan compatible).
 * One SQLite-backed Durable Object per sync group (protocol 2) plus a short-lived pairing mailbox; WebSockets use the hibernation API.
 * Unknown group ids are not turned into Durable Objects unless the request is a verified genesis or seed.
 */
import { DurableObject } from 'cloudflare:workers';
import { TokenBucket, err } from './core';
import {
  ChangeInsert, ChangeRow, GID2_RE, GroupStoreV2, LIMITS2, PID_RE, PairStore, accessSecretMatches, accessSecretOk, authenticate,
  changesFrame2, configuredAccessSecret, corsHeaders2, discardEmptyProbe, handleGroupV2, handlePair, healthResponse2, parsePathV2,
  retentionAction, verifyCreateGroupRequest, webCrypto2,
} from './core2';
import { PairSlot, hex, currentEpoch, type GroupState } from './proto2';

export interface Env {
  GROUPS_V2: DurableObjectNamespace<GroupV2DO>;
  PAIRS: DurableObjectNamespace<PairDO>;
  REGISTRY?: DurableObjectNamespace<RegistryDO>;
  /** Optional Workers Rate Limiting binding (per client IP). */
  IP_LIMITER?: { limit(o: { key: string }): Promise<{ success: boolean }> };
  HEALTH_LIMITER?: { limit(o: { key: string }): Promise<{ success: boolean }> };
  ALLOC_LIMITER?: { limit(o: { key: string }): Promise<{ success: boolean }> };
  /** Days of inactivity after which a group's data is deleted, and the age after which snapshot-covered history is pruned (default 90). */
  RETENTION_DAYS_V2?: string;
  /** Optional per-relay access key. When unset or empty, the relay accepts requests without it (older deployments). */
  RELAY_ACCESS_SECRET?: string;
}

async function rateLimit(req: Request, limiter: Env['IP_LIMITER']): Promise<Response | null> {
  if (!limiter) return null;
  const ip = req.headers.get('cf-connecting-ip') ?? 'unknown';
  const { success } = await limiter.limit({ key: ip });
  return success ? null : err(429, 'rate_limited', { ...corsHeaders2(), 'retry-after': '10' });
}

async function registryCall(env: Env, path: '/has' | '/add' | '/del', kind: 'gid' | 'pid', id: string): Promise<{ known?: boolean } | null> {
  if (!env.REGISTRY) return null;
  const stub = env.REGISTRY.get(env.REGISTRY.idFromName('registry'));
  const res = await stub.fetch(new Request('https://registry' + path, {
    method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ kind, id }),
  }));
  try { return await res.json() as { known?: boolean }; } catch { return null; }
}

export default {
  async fetch(req: Request, env: Env): Promise<Response> {
    const url = new URL(req.url);
    if (req.method === 'OPTIONS') return new Response(null, { status: 204, headers: corsHeaders2() });
    if (url.pathname === '/v2/health' || url.pathname === '/') {
      const lim = await rateLimit(req, env.HEALTH_LIMITER ?? env.IP_LIMITER);
      if (lim) return lim;
      if (!(await accessSecretOk(req, env.RELAY_ACCESS_SECRET))) return err(401, 'unauthorized', corsHeaders2());
      return healthResponse2('cloudflare-worker');
    }
    const p2 = parsePathV2(url.pathname);
    if (!p2) return err(404, 'not_found', corsHeaders2());
    // Pairing does not use the access key (the joining device learns it from the encrypted offer). When the key
    // is configured, pairing instead requires a proof derived from the pairing secret (see handlePair).
    // WebSocket upgrades also skip the header check: browsers cannot set custom headers, so the key is carried
    // in the first auth frame. Nothing is stored or sent until that frame is accepted.
    const isWs = req.headers.get('upgrade')?.toLowerCase() === 'websocket';
    if (p2.kind !== 'pair' && !isWs && !(await accessSecretOk(req, env.RELAY_ACCESS_SECRET))) return err(401, 'unauthorized', corsHeaders2());
    const lim = await rateLimit(req, env.IP_LIMITER);
    if (lim) return lim;
    if (p2.kind === 'group') {
      if (!GID2_RE.test(p2.gid)) return err(400, 'bad_group_id', corsHeaders2());
      const known = !!(await registryCall(env, '/has', 'gid', p2.gid))?.known;
      if (!known) {
        const raw = await req.arrayBuffer();
        const body = new Uint8Array(raw);
        const okCreate = await verifyCreateGroupRequest(webCrypto2, p2.gid, req.method, url.pathname, url.search, body, req.headers.get('authorization'));
        if (!okCreate) return err(401, 'unauthorized', corsHeaders2());
        const alloc = await rateLimit(req, env.ALLOC_LIMITER);
        if (alloc) return alloc;
        const forwarded = new Request(req.url, { method: req.method, headers: req.headers, body: raw.byteLength ? raw : undefined });
        const res = await env.GROUPS_V2.get(env.GROUPS_V2.idFromName('g:' + p2.gid)).fetch(forwarded);
        // 409 log_conflict means this relay already holds the group (e.g. after an update that reset the registry).
        if (res.ok || res.status === 409) await registryCall(env, '/add', 'gid', p2.gid);
        return res;
      }
      const res = await env.GROUPS_V2.get(env.GROUPS_V2.idFromName('g:' + p2.gid)).fetch(req);
      if (req.method === 'DELETE' && res.ok) await registryCall(env, '/del', 'gid', p2.gid);
      return res;
    }
    if (!PID_RE.test(p2.pid)) return err(400, 'bad_pairing_id', corsHeaders2());
    if (req.method === 'PUT') {
      const alloc = await rateLimit(req, env.ALLOC_LIMITER);
      if (alloc) return alloc;
    }
    return env.PAIRS.get(env.PAIRS.idFromName('p:' + p2.pid)).fetch(req);
  },
} satisfies ExportedHandler<Env>;

class SqlGroupStoreV2 implements GroupStoreV2 {
  private ready = false;
  constructor(private sql: SqlStorage) {}
  private hasLogTable() {
    return this.sql.exec("SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'log' LIMIT 1").toArray().length > 0;
  }
  private ensure() {
    if (this.ready) return;
    this.sql.exec('CREATE TABLE IF NOT EXISTS log (idx INTEGER PRIMARY KEY, entry BLOB NOT NULL, hash BLOB NOT NULL)');
    this.sql.exec(`CREATE TABLE IF NOT EXISTS changes (
      seq INTEGER PRIMARY KEY AUTOINCREMENT, device TEXT NOT NULL, epoch INTEGER NOT NULL, idx INTEGER NOT NULL,
      kind INTEGER NOT NULL, day INTEGER NOT NULL, blob BLOB NOT NULL, size INTEGER NOT NULL, UNIQUE(device, epoch, idx))`);
    this.sql.exec('CREATE TABLE IF NOT EXISTS nonces (n TEXT PRIMARY KEY, exp INTEGER NOT NULL)');
    this.sql.exec('CREATE TABLE IF NOT EXISTS meta (k TEXT PRIMARY KEY, v INTEGER)');
    this.ready = true;
  }
  private readable() {
    if (this.ready) return true;
    if (this.hasLogTable()) { this.ready = true; return true; }
    return false;
  }
  logLength() { return this.readable() ? this.sql.exec<{ c: number }>('SELECT COUNT(*) AS c FROM log').one().c : 0; }
  private lastRow() { const r = this.sql.exec<{ entry: ArrayBuffer; hash: ArrayBuffer }>('SELECT entry, hash FROM log ORDER BY idx DESC LIMIT 1').toArray(); return r[0] ?? null; }
  logHead() { if (!this.readable()) return null; const r = this.lastRow(); return r ? new Uint8Array(r.hash) : null; }
  logLast() { if (!this.readable()) return null; const r = this.lastRow(); return r ? new Uint8Array(r.entry) : null; }
  logEntries(from: number, limit: number) { return this.readable() ? this.sql.exec<{ entry: ArrayBuffer }>('SELECT entry FROM log WHERE idx >= ? ORDER BY idx LIMIT ?', from, limit).toArray().map((r) => new Uint8Array(r.entry)) : []; }
  logAppend(raw: Uint8Array, hash: Uint8Array) { this.ensure(); this.sql.exec('INSERT INTO log (idx, entry, hash) VALUES ((SELECT COUNT(*) FROM log), ?, ?)', raw, hash); }
  insert(items: ChangeInsert[]) {
    this.ensure();
    return items.map((it) => {
      const ex = this.sql.exec<{ seq: number }>('SELECT seq FROM changes WHERE device = ? AND epoch = ? AND idx = ?', it.device, it.epoch, it.index).toArray();
      if (ex.length) return { seq: ex[0].seq, duplicate: true };
      const row = this.sql.exec<{ seq: number }>('INSERT INTO changes (device, epoch, idx, kind, day, blob, size) VALUES (?, ?, ?, ?, ?, ?, ?) RETURNING seq',
        it.device, it.epoch, it.index, it.kind, it.day, it.blob, it.blob.length).one();
      return { seq: row.seq, duplicate: false };
    });
  }
  since(since: number, limit: number): ChangeRow[] {
    return this.readable() ? this.sql.exec<{ seq: number; blob: ArrayBuffer }>('SELECT seq, blob FROM changes WHERE seq > ? ORDER BY seq LIMIT ?', since, limit).toArray().map((r) => ({ seq: r.seq, blob: new Uint8Array(r.blob) })) : [];
  }
  latest() { if (!this.readable()) return 0; const r = this.sql.exec<{ seq: number }>("SELECT seq FROM sqlite_sequence WHERE name = 'changes'").toArray(); return r.length ? r[0].seq : 0; }
  usage() { if (!this.readable()) return { count: 0, bytes: 0 }; const r = this.sql.exec<{ c: number; b: number | null }>('SELECT COUNT(*) AS c, SUM(size) AS b FROM changes').one(); return { count: r.c, bytes: r.b ?? 0 }; }
  nonceUsed(n: string, now: number) {
    this.ensure();
    if (this.sql.exec('SELECT 1 FROM nonces WHERE n = ?', n).toArray().length) return true;
    this.sql.exec('INSERT INTO nonces (n, exp) VALUES (?, ?)', n, now + LIMITS2.nonceTtlMs);
    return false;
  }
  pruneNonces(now: number) { if (this.readable()) this.sql.exec('DELETE FROM nonces WHERE exp < ?', now); }
  compact(upto: number) { return this.readable() ? this.sql.exec('DELETE FROM changes WHERE seq <= ?', upto).rowsWritten : 0; }
  hasSnapshotAfter(seq: number) { return this.readable() && this.sql.exec('SELECT 1 FROM changes WHERE seq > ? AND kind = 2 LIMIT 1', seq).toArray().length > 0; }
  pruneOld(nowDay: number, retention: number) {
    if (!this.readable()) return 0;
    const r = this.sql.exec<{ m: number | null }>('SELECT MAX(seq) AS m FROM changes WHERE kind = 2').one();
    if (!r.m) return 0;
    return this.sql.exec('DELETE FROM changes WHERE day < ? AND seq < ?', nowDay - retention, r.m).rowsWritten;
  }
  lastWriteDay() { if (!this.readable()) return null; const r = this.sql.exec<{ v: number }>("SELECT v FROM meta WHERE k = 'lwd'").toArray(); return r.length ? r[0].v : null; }
  setLastWriteDay(d: number) { this.ensure(); this.sql.exec("INSERT INTO meta (k, v) VALUES ('lwd', ?) ON CONFLICT(k) DO UPDATE SET v = excluded.v", d); }
  clearAll() { if (!this.readable()) return; this.sql.exec('DELETE FROM changes'); this.sql.exec('DELETE FROM log'); this.sql.exec('DELETE FROM nonces'); this.sql.exec('DELETE FROM meta'); }
}

interface WsAtt { authed: boolean; deadline: number; since: number; gid: string; device?: string }

export class GroupV2DO extends DurableObject<Env> {
  private store: SqlGroupStoreV2;
  private pushBucket = new TokenBucket(LIMITS2.pushRate.capacity, LIMITS2.pushRate.refillPerSec);
  private readBucket = new TokenBucket(LIMITS2.readRate.capacity, LIMITS2.readRate.refillPerSec);
  constructor(ctx: DurableObjectState, env: Env) { super(ctx, env); this.store = new SqlGroupStoreV2(ctx.storage.sql); }

  private gidOf(req: Request) { const p = parsePathV2(new URL(req.url).pathname); return p && p.kind === 'group' ? p : null; }

  private async dropIfEmpty() {
    if (discardEmptyProbe(this.store)) await this.ctx.storage.deleteAll();
  }

  async fetch(req: Request): Promise<Response> {
    const p = this.gidOf(req);
    if (!p) return err(404, 'not_found', corsHeaders2());
    if (p.sub === '/ws') return this.upgrade(req, new URL(req.url), p.gid);
    const res = await handleGroupV2(req, p.sub, {
      gid: p.gid, store: this.store, pushBucket: this.pushBucket, readBucket: this.readBucket, crypto: webCrypto2,
      broadcast: (c) => this.broadcast(c),
      onMembers: (ids) => this.dropNonMembers(ids),
      onDeleted: () => { for (const ws of this.ctx.getWebSockets()) { try { ws.close(4000, 'group deleted'); } catch { /* */ } } },
    });
    if (discardEmptyProbe(this.store)) { await this.ctx.storage.deleteAll(); return res; }
    if (req.method !== 'GET' && res.ok) await this.ensureAlarm();
    return res;
  }

  private async ensureAlarm() { if ((await this.ctx.storage.getAlarm()) === null) await this.ctx.storage.setAlarm(Date.now() + 86_400_000); }

  /** Daily: drop empty leftovers and inactive groups (default 90 days), and snapshot-covered history older than the retention. */
  async alarm() {
    if (discardEmptyProbe(this.store)) { await this.ctx.storage.deleteAll(); return; }
    const days = Number(this.env.RETENTION_DAYS_V2 ?? LIMITS2.retentionDays);
    retentionAction(this.store, Date.now(), days > 0 ? days : LIMITS2.retentionDays);
    this.sweepUnauthed();
    if (this.store.logLength() > 0) await this.ctx.storage.setAlarm(Date.now() + 86_400_000);
  }

  private sweepUnauthed() {
    const now = Date.now();
    for (const ws of this.ctx.getWebSockets()) {
      const a = ws.deserializeAttachment() as WsAtt | null;
      if (!a || (!a.authed && now > a.deadline)) { try { ws.close(4401, 'auth timeout'); } catch { /* */ } }
    }
  }

  private dropNonMembers(ids: Set<string>) {
    for (const ws of this.ctx.getWebSockets()) {
      const a = ws.deserializeAttachment() as WsAtt | null;
      if (a?.authed && a.device && !ids.has(a.device)) { try { ws.close(4403, 'removed'); } catch { /* */ } }
    }
  }

  private async upgrade(req: Request, url: URL, gid: string): Promise<Response> {
    if (req.headers.get('upgrade')?.toLowerCase() !== 'websocket') return err(426, 'expected_websocket', corsHeaders2());
    this.sweepUnauthed();
    if (this.ctx.getWebSockets().length >= LIMITS2.maxSocketsPerGroup) return err(429, 'too_many_sockets', corsHeaders2());
    const since = Number(url.searchParams.get('since') ?? '0');
    const sinceN = Number.isSafeInteger(since) && since >= 0 ? since : 0;
    const header = req.headers.get('authorization');
    if (header) {
      if (!(await accessSecretOk(req, this.env.RELAY_ACCESS_SECRET))) { await this.dropIfEmpty(); return err(401, 'unauthorized', corsHeaders2()); }
      const r = await authenticate({ gid, store: this.store, pushBucket: this.pushBucket, readBucket: this.readBucket, crypto: webCrypto2, broadcast: () => {} },
        { method: 'WS', path: `/v2/g/${gid}/ws`, search: `?since=${sinceN}`, body: new Uint8Array(0), header });
      if (!r.ok) { await this.dropIfEmpty(); return r.res; }
      const pair = new WebSocketPair();
      const [client, server] = [pair[0], pair[1]];
      this.ctx.acceptWebSocket(server);
      const att: WsAtt = { authed: true, deadline: Date.now() + LIMITS2.wsAuthTimeoutMs, gid, since: sinceN, device: r.member.id };
      server.serializeAttachment(att);
      this.sendBacklog(server, att, r.state);
      await this.ensureAlarm();
      return new Response(null, { status: 101, webSocket: client });
    }
    const pair = new WebSocketPair();
    const [client, server] = [pair[0], pair[1]];
    this.ctx.acceptWebSocket(server);
    // Nothing is stored and nothing is sent until the client proves membership with a signed auth frame.
    const att: WsAtt = { authed: false, deadline: Date.now() + LIMITS2.wsAuthTimeoutMs, gid, since: sinceN };
    server.serializeAttachment(att);
    return new Response(null, { status: 101, webSocket: client });
  }

  private sendBacklog(ws: WebSocket, att: WsAtt, state: GroupState) {
    let cur = att.since;
    for (let i = 0; i < 20; i++) {
      const rows = this.store.since(cur, 100);
      if (!rows.length) break;
      ws.send(changesFrame2(rows));
      cur = rows[rows.length - 1].seq;
      if (rows.length < 100) break;
    }
    ws.send(JSON.stringify({ type: 'ready', latest: this.store.latest(), epoch: currentEpoch(state), head: hex(state.head), logLength: state.length }));
  }

  private broadcast(changes: ChangeRow[]) {
    const frame = changesFrame2(changes);
    for (const ws of this.ctx.getWebSockets()) {
      const a = ws.deserializeAttachment() as WsAtt | null;
      if (a?.authed) { try { ws.send(frame); } catch { /* closed */ } }
    }
  }

  async webSocketMessage(ws: WebSocket, msg: string | ArrayBuffer) {
    const att = ws.deserializeAttachment() as WsAtt | null;
    if (!att) return ws.close(4401, 'no state');
    if (att.authed) { if (msg === 'ping') ws.send('pong'); return; }
    if (Date.now() > att.deadline) { try { ws.close(4401, 'auth timeout'); } catch { /* */ } await this.dropIfEmpty(); return; }
    let f: any;
    try { f = JSON.parse(typeof msg === 'string' ? msg : new TextDecoder().decode(msg)); } catch { try { ws.close(4401, 'bad frame'); } catch { /* */ } await this.dropIfEmpty(); return; }
    if (f?.type !== 'auth') { try { ws.close(4401, 'auth required'); } catch { /* */ } await this.dropIfEmpty(); return; }
    const provided = typeof f.k === 'string' ? f.k : '';
    if (!(await accessSecretMatches(provided, this.env.RELAY_ACCESS_SECRET))) { try { ws.close(4401, 'unauthorized'); } catch { /* */ } await this.dropIfEmpty(); return; }
    const gid = att.gid;
    const header = `PCS2 d=${f.d},t=${f.t},n=${f.n},s=${f.s}`;
    const search = `?since=${att.since}`;
    const w = this.readBucket.take(1);
    if (w) return ws.close(4429, 'rate limited');
    const r = await authenticate({ gid, store: this.store, pushBucket: this.pushBucket, readBucket: this.readBucket, crypto: webCrypto2, broadcast: () => {} },
      { method: 'WS', path: `/v2/g/${gid}/ws`, search, body: new Uint8Array(0), header });
    if (!r.ok) { try { ws.close(4401, 'unauthorized'); } catch { /* */ } await this.dropIfEmpty(); return; }
    ws.serializeAttachment({ ...att, authed: true, device: r.member.id } satisfies WsAtt);
    let cur = att.since;
    for (let i = 0; i < 20; i++) {
      const rows = this.store.since(cur, 100);
      if (!rows.length) break;
      ws.send(changesFrame2(rows));
      cur = rows[rows.length - 1].seq;
      if (rows.length < 100) break;
    }
    ws.send(JSON.stringify({ type: 'ready', latest: this.store.latest(), epoch: currentEpoch(r.state), head: hex(r.state.head), logLength: r.state.length }));
    await this.ensureAlarm();
  }

  async webSocketClose(ws: WebSocket, code: number) { try { ws.close(code === 1005 ? 1000 : code, 'bye'); } catch { /* */ } }
}

class SqlPairStore implements PairStore {
  private ready = false;
  constructor(private sql: SqlStorage) {}
  private hasTable() { return this.sql.exec("SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'slots' LIMIT 1").toArray().length > 0; }
  private ensure() {
    if (this.ready) return;
    this.sql.exec('CREATE TABLE IF NOT EXISTS slots (slot TEXT PRIMARY KEY, blob BLOB NOT NULL, at INTEGER NOT NULL)');
    this.sql.exec('CREATE TABLE IF NOT EXISTS pair_meta (k TEXT PRIMARY KEY, v BLOB NOT NULL)');
    this.ready = true;
  }
  private readable() { if (this.ready) return true; if (this.hasTable()) { this.ensure(); return true; } return false; }
  get(slot: PairSlot) { if (!this.readable()) return null; const r = this.sql.exec<{ blob: ArrayBuffer; at: number }>('SELECT blob, at FROM slots WHERE slot = ?', slot).toArray(); return r.length ? { blob: new Uint8Array(r[0].blob), at: r[0].at } : null; }
  put(slot: PairSlot, blob: Uint8Array, at: number) {
    this.ensure();
    if (this.sql.exec('SELECT 1 FROM slots WHERE slot = ?', slot).toArray().length) return false;
    this.sql.exec('INSERT INTO slots (slot, blob, at) VALUES (?, ?, ?)', slot, blob, at);
    return true;
  }
  firstAt() { if (!this.readable()) return null; const r = this.sql.exec<{ m: number | null }>('SELECT MIN(at) AS m FROM slots').one(); return r.m; }
  clear() { if (this.readable()) { this.sql.exec('DELETE FROM slots'); this.sql.exec('DELETE FROM pair_meta'); } }
  getVerifier() {
    if (!this.readable()) return null;
    const r = this.sql.exec<{ v: ArrayBuffer }>("SELECT v FROM pair_meta WHERE k = 'vk'").toArray();
    return r.length ? new Uint8Array(r[0].v) : null;
  }
  setVerifier(pk: Uint8Array) {
    this.ensure();
    if (this.sql.exec("SELECT 1 FROM pair_meta WHERE k = 'vk'").toArray().length) return false;
    this.sql.exec("INSERT INTO pair_meta (k, v) VALUES ('vk', ?)", pk);
    return true;
  }
}

/** One-time pairing mailbox (ciphertext only, write-once, 10 minute lifetime). */
export class PairDO extends DurableObject<Env> {
  private store: SqlPairStore;
  constructor(ctx: DurableObjectState, env: Env) { super(ctx, env); this.store = new SqlPairStore(ctx.storage.sql); }
  async fetch(req: Request): Promise<Response> {
    const p = parsePathV2(new URL(req.url).pathname);
    if (!p || p.kind !== 'pair') return err(404, 'not_found', corsHeaders2());
    const res = await handlePair(req, p.slot, this.store, Date.now(), { requireProof: !!configuredAccessSecret(this.env.RELAY_ACCESS_SECRET) });
    if (this.store.firstAt() === null) { await this.ctx.storage.deleteAll(); return res; }
    if (req.method === 'PUT' && res.ok) await this.ctx.storage.setAlarm(Date.now() + LIMITS2.pairTtlMs + 1000);
    return res;
  }
  async alarm() { this.store.clear(); await this.ctx.storage.deleteAll(); }
}

/** Remembers group ids that have been successfully created or seeded, so probes never instantiate a group Durable Object. */
export class RegistryDO extends DurableObject<Env> {
  constructor(ctx: DurableObjectState, env: Env) {
    super(ctx, env);
    ctx.storage.sql.exec('CREATE TABLE IF NOT EXISTS known (kind TEXT NOT NULL, id TEXT NOT NULL, PRIMARY KEY (kind, id))');
  }
  async fetch(req: Request): Promise<Response> {
    const url = new URL(req.url);
    let body: { kind?: string; id?: string } = {};
    try { body = await req.json() as { kind?: string; id?: string }; } catch { /* */ }
    const kind = body.kind === 'pid' || body.kind === 'gid' ? body.kind : '';
    const id = typeof body.id === 'string' ? body.id : '';
    if (!kind || !id) return new Response(JSON.stringify({ error: 'bad_request' }), { status: 400 });
    if (url.pathname === '/has' && req.method === 'POST') {
      const n = this.ctx.storage.sql.exec('SELECT 1 FROM known WHERE kind = ? AND id = ?', kind, id).toArray().length;
      return Response.json({ known: n > 0 });
    }
    if (url.pathname === '/add' && req.method === 'POST') {
      this.ctx.storage.sql.exec('INSERT OR IGNORE INTO known (kind, id) VALUES (?, ?)', kind, id);
      return Response.json({ ok: true });
    }
    if (url.pathname === '/del' && req.method === 'POST') {
      this.ctx.storage.sql.exec('DELETE FROM known WHERE kind = ? AND id = ?', kind, id);
      return Response.json({ ok: true });
    }
    return new Response(JSON.stringify({ error: 'not_found' }), { status: 404 });
  }
}
