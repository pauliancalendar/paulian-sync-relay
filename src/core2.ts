/**
 * Paulian Sync relay, protocol v2 core. Platform-neutral (WebCrypto + Fetch), shared with the Node
 * self-host via scripts/vendor-relay-core.sh. See docs/PROTOCOL_V2.md.
 *
 * What the relay enforces (it never sees plaintext):
 *   - EVERY group read and write is a per-device Ed25519-signed request (method, path, query, body hash,
 *     timestamp within +-5 min, single-use nonce). Knowing the group id grants nothing.
 *   - The caller must be a CURRENT member in the signed membership log; a removed device is locked out at once.
 *   - Membership entries are validated (hash chain, signer is a member, add/remove/rotate rules, key packages).
 *   - Changes must be exactly a power-of-two size bucket (>= 4 KiB), signed by the sending member, in the
 *     CURRENT epoch, unique per (device, epoch, index).
 *   - The relay stores a coarse UTC day per change, not a timestamp; unknown-group, non-member and bad-signature
 *     requests are indistinguishable (401).
 */
import {
  Crypto2, GroupState, Kind, LogType, MAX_BUCKET, REQ_SKEW_MS, applyLogEntry, b64uDecode, b64uEncode, canonicalRequest,
  currentEpoch, emptyState, hex, parseAuth, parseEnvelope, parseLogEntry, unhex, verifyEnvelopeSig, Member, PAIR_SLOTS, PairSlot,
} from './proto2';
import { TokenBucket, json, err, corsHeaders } from './core';

export const PROTOCOL_VERSION_V2 = 2;
export const LIMITS2 = {
  maxBodyBytes: 3 * 1024 * 1024,
  maxChangesPerPush: 100,
  maxFetchLimit: 500,
  groupQuotaBytes: 64 * 1024 * 1024,
  groupQuotaCount: 50_000,
  maxSocketsPerGroup: 16,
  nonceTtlMs: 15 * 60 * 1000,
  pushRate: { capacity: 60, refillPerSec: 1 },
  readRate: { capacity: 120, refillPerSec: 4 },
  pairTtlMs: 10 * 60 * 1000,
  pairMaxBlob: 2048,
  wsAuthTimeoutMs: 10_000,
  /** Default inactivity / snapshot-covered history retention (days). */
  retentionDays: 90,
};

export const GID2_RE = /^[0-9a-f]{64}$/;
export const PID_RE = /^[0-9a-f]{32}$/;
const bs = (u: Uint8Array) => u as unknown as BufferSource;

export interface ChangeRow { seq: number; blob: Uint8Array }
export interface ChangeInsert { device: string; epoch: number; index: number; kind: number; day: number; blob: Uint8Array }

/** Synchronous storage for ONE group. Implemented with SQLite (Durable Object) and in memory (tests / self-host). */
export interface GroupStoreV2 {
  logLength(): number;
  logHead(): Uint8Array | null;
  logLast(): Uint8Array | null;
  logEntries(from: number, limit: number): Uint8Array[];
  logAppend(raw: Uint8Array, hash: Uint8Array): void;
  insert(items: ChangeInsert[]): Array<{ seq: number; duplicate: boolean }>;
  since(since: number, limit: number): ChangeRow[];
  latest(): number;
  usage(): { count: number; bytes: number };
  /** True if the nonce was already used (and records it otherwise). */
  nonceUsed(nonce: string, nowMs: number): boolean;
  pruneNonces(nowMs: number): void;
  compact(upto: number): number;
  hasSnapshotAfter(seq: number): boolean;
  /** Delete history older than the retention that is covered by a newer snapshot. Returns rows deleted. */
  pruneOld(nowDay: number, retentionDays: number): number;
  lastWriteDay(): number | null;
  setLastWriteDay(day: number): void;
  clearAll(): void;
}

export interface GroupContext2 {
  gid: string;
  store: GroupStoreV2;
  pushBucket: TokenBucket;
  readBucket: TokenBucket;
  crypto: Crypto2;
  now?: () => number;
  broadcast(changes: ChangeRow[]): void;
  /** Membership changed: close sockets whose device is not in `memberIds`. */
  onMembers?(memberIds: Set<string>): void;
  onDeleted?(): void;
}

// ---------- crypto (WebCrypto) ----------
export const webCrypto2: Crypto2 = {
  async sha256(b) { return new Uint8Array(await crypto.subtle.digest('SHA-256', bs(b))); },
  async verify(pk, msg, sig) {
    try {
      const key = await crypto.subtle.importKey('raw', bs(pk), { name: 'Ed25519' }, false, ['verify']);
      return await crypto.subtle.verify({ name: 'Ed25519' }, key, bs(sig), bs(msg));
    } catch { return false; }
  },
};

export function corsHeaders2(): Record<string, string> {
  return { ...corsHeaders(), 'access-control-allow-methods': 'GET, POST, PUT, DELETE, OPTIONS', 'access-control-allow-headers': 'content-type, authorization' };
}
const J = (body: unknown, status = 200, extra: Record<string, string> = {}) => json(body, status, { ...corsHeaders2(), ...extra });
const E = (status: number, code: string, extra: Record<string, string> = {}) => err(status, code, { ...corsHeaders2(), ...extra });

/** Self-reported signature the apps look for on /v1/health (a sanity check against typos and look-alike Workers, not authentication). */
export const RELAY_SERVICE_ID = 'paulian-sync-relay';

/**
 * The relay software version, "major.minor.patch" (keep equal to package.json "version"). The apps compare it with the newest
 * and the oldest version they know: older than newest -> "an update is available"; older than their minimum -> sync is paused until
 * the relay is updated. Bump it whenever the relay's behaviour changes, and add the entry to UPDATE.md.
 * A relay that reports no `relayVersion` is a 1.0.0 relay (the field was added in 1.1.0).
 */
export const RELAY_VERSION = '1.1.0';

export function healthResponse2(impl: string, v1Mode: string): Response {
  return J({ ok: true, service: RELAY_SERVICE_ID, relayVersion: RELAY_VERSION, protocol: PROTOCOL_VERSION_V2, versions: v1Mode === 'off' ? [2] : [1, 2], v1: v1Mode, impl });
}

export function parsePathV2(pathname: string): { kind: 'group'; gid: string; sub: string } | { kind: 'pair'; pid: string; slot: string } | null {
  let m = /^\/v2\/g\/([^/]+)(\/[a-z]+)?\/?$/.exec(pathname);
  if (m) return { kind: 'group', gid: m[1], sub: m[2] ?? '' };
  m = /^\/v2\/pair\/([^/]+)\/([a-z]+)\/?$/.exec(pathname);
  if (m) return { kind: 'pair', pid: m[1], slot: m[2] };
  return null;
}

async function readBody(req: Request, max: number): Promise<Uint8Array | Response> {
  const len = Number(req.headers.get('content-length') ?? '0');
  if (len > max) return E(413, 'body_too_large');
  if (!req.body) return new Uint8Array(0);
  const reader = req.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.length;
    if (total > max) { try { await reader.cancel(); } catch { /* */ } return E(413, 'body_too_large'); }
    chunks.push(value);
  }
  const o = new Uint8Array(total);
  let i = 0;
  for (const c of chunks) { o.set(c, i); i += c.length; }
  return o;
}

export function stateOf(store: GroupStoreV2): GroupState {
  const n = store.logLength();
  const last = store.logLast();
  if (!n || !last) return emptyState();
  const e = parseLogEntry(last)!;
  return { length: n, head: store.logHead()!, members: e.members, epochDay: e.day };
}

export type AuthResult = { ok: true; member: Member; state: GroupState } | { ok: false; res: Response };

/**
 * Verifies one signed request or WebSocket auth frame. All failures after the timestamp check use the same
 * generic 401 so the relay never confirms that a group exists. `genesisMember` is used only for the request
 * that creates the group (the key is then taken from the entry, which binds it to the group id).
 */
export async function authenticate(ctx: GroupContext2, a: { method: string; path: string; search: string; body: Uint8Array; header: string | null }, genesisMember?: Member, seed = false): Promise<AuthResult> {
  const now = ctx.now?.() ?? Date.now();
  const h = parseAuth(a.header);
  if (!h) return { ok: false, res: E(401, 'unauthorized') };
  if (Math.abs(now - h.t) > REQ_SKEW_MS) return { ok: false, res: E(401, 'stale_timestamp') };
  const state = stateOf(ctx.store);
  const member = genesisMember && (state.length === 0 || seed) ? genesisMember : state.members.find((m) => m.id === h.d);
  if (!member || member.id !== h.d) return { ok: false, res: E(401, 'unauthorized') };
  const sig = b64uDecode(h.s);
  if (!sig || sig.length !== 64) return { ok: false, res: E(401, 'unauthorized') };
  const msg = await canonicalRequest(ctx.crypto, a.method, a.path, a.search, a.body, h.t, h.n, h.d);
  if (!(await ctx.crypto.verify(member.ed, msg, sig))) return { ok: false, res: E(401, 'unauthorized') };
  // Record the nonce only after the signature verified, so unauthenticated floods cannot fill the table.
  ctx.store.pruneNonces(now);
  if (ctx.store.nonceUsed(h.n, now)) return { ok: false, res: E(401, 'replayed_request') };
  return { ok: true, member, state };
}

function rateLimited(ms: number): Response {
  return E(429, 'rate_limited', { 'retry-after': String(Math.max(1, Math.ceil(ms / 1000))) });
}
const dayOf = (now: number) => Math.floor(now / 86_400_000);

export function changesFrame2(changes: ChangeRow[]): string {
  return JSON.stringify({ type: 'changes', changes: changes.map((c) => ({ seq: c.seq, blob: b64uEncode(c.blob) })) });
}

/**
 * Seed or extend the log with several entries at once ({entries:[...]}, 1..64). Used when a device adds a relay that
 * has never seen the group: only it holds the whole log, and the entries are self-authenticating (every one is
 * verified against the previous state). The caller must be a member in the state the batch ends in.
 */
async function seedLog(list: unknown[], ctx: GroupContext2, authArgs: { method: string; path: string; search: string; body: Uint8Array; header: string | null }, now: number): Promise<Response> {
  if (!list.length || list.length > 64 || !list.every((x) => typeof x === 'string')) return E(400, 'bad_entry');
  const raws: Uint8Array[] = [];
  for (const x of list as string[]) { const b = b64uDecode(x); if (!b) return E(400, 'bad_entry'); raws.push(b); }
  const h = parseAuth(authArgs.header);
  if (!h) return E(401, 'unauthorized');
  const w = ctx.pushBucket.take(1, now);
  if (w) return rateLimited(w);
  let st = stateOf(ctx.store);
  const start = st.length;
  for (const raw of raws) {
    const r = await applyLogEntry(ctx.crypto, unhex(ctx.gid), st, raw);
    if (!r.ok) return r.error === 'bad_index' || r.error === 'bad_prev' ? J({ error: 'log_conflict', length: start, head: start ? hex(st.head) : '' }, 409) : E(400, r.error);
    st = r.state;
  }
  const caller = st.members.find((m) => m.id === h.d);
  if (!caller) return E(401, 'unauthorized');
  const auth = await authenticate(ctx, authArgs, caller, true);
  if (!auth.ok) return auth.res;
  let st2 = stateOf(ctx.store);
  for (const raw of raws) {
    const r = await applyLogEntry(ctx.crypto, unhex(ctx.gid), st2, raw);
    if (!r.ok) return E(400, r.error);
    ctx.store.logAppend(raw, r.state.head);
    st2 = r.state;
  }
  ctx.store.setLastWriteDay(dayOf(now));
  ctx.onMembers?.(new Set(st2.members.map((m) => m.id)));
  return J({ index: st2.length - 1, length: st2.length, head: hex(st2.head) });
}

/** Handles everything under /v2/g/{gid}/ except the WebSocket upgrade. `sub` is "/changes", "/log", "/compact" or "". */
export async function handleGroupV2(req: Request, sub: string, ctx: GroupContext2): Promise<Response> {
  const now = ctx.now?.() ?? Date.now();
  if (req.method === 'OPTIONS') return new Response(null, { status: 204, headers: corsHeaders2() });
  const url = new URL(req.url);
  const body = await readBody(req, LIMITS2.maxBodyBytes);
  if (body instanceof Response) return body;
  const authArgs = { method: req.method, path: url.pathname, search: url.search, body, header: req.headers.get('authorization') };

  // ----- create / extend the membership log -----
  if (sub === '/log' && req.method === 'POST') {
    let j: any;
    try { j = JSON.parse(new TextDecoder().decode(body)); } catch { return E(400, 'bad_json'); }
    if (Array.isArray(j?.entries)) return seedLog(j.entries, ctx, authArgs, now);
    const raw = typeof j?.entry === 'string' ? b64uDecode(j.entry) : null;
    const parsed = raw ? parseLogEntry(raw) : null;
    if (!raw || !parsed) return E(400, 'bad_entry');
    const genesisMember = parsed.type === LogType.Genesis ? parsed.members[0] : undefined;
    const auth = await authenticate(ctx, authArgs, genesisMember);
    if (!auth.ok) return auth.res;
    const w = ctx.pushBucket.take(1, now);
    if (w) return rateLimited(w);
    if (auth.member.id !== parsed.signer) return E(403, 'signer_mismatch');
    const r = await applyLogEntry(ctx.crypto, unhex(ctx.gid), auth.state, raw);
    if (!r.ok) return r.error === 'bad_index' || r.error === 'bad_prev' ? J({ error: 'log_conflict', length: auth.state.length, head: hex(auth.state.head) }, 409) : E(400, r.error);
    ctx.store.logAppend(raw, r.state.head);
    ctx.store.setLastWriteDay(dayOf(now));
    ctx.onMembers?.(new Set(r.state.members.map((m) => m.id)));
    return J({ index: r.entry.index, length: r.state.length, head: hex(r.state.head) });
  }

  const auth = await authenticate(ctx, authArgs);
  if (!auth.ok) return auth.res;
  const { member, state } = auth;

  if (sub === '/log' && req.method === 'GET') {
    const w = ctx.readBucket.take(1, now);
    if (w) return rateLimited(w);
    const from = Number(url.searchParams.get('from') ?? '0');
    if (!Number.isSafeInteger(from) || from < 0) return E(400, 'bad_from');
    return J({ entries: ctx.store.logEntries(from, 64).map(b64uEncode), length: state.length, head: hex(state.head) });
  }

  if (sub === '/changes' && req.method === 'GET') {
    const w = ctx.readBucket.take(1, now);
    if (w) return rateLimited(w);
    const since = Number(url.searchParams.get('since') ?? '0');
    const limit = Math.min(LIMITS2.maxFetchLimit, Math.max(1, Number(url.searchParams.get('limit') ?? '200') || 200));
    if (!Number.isSafeInteger(since) || since < 0) return E(400, 'bad_since');
    const rows = ctx.store.since(since, limit + 1);
    const more = rows.length > limit;
    const page = more ? rows.slice(0, limit) : rows;
    return J({
      changes: page.map((c) => ({ seq: c.seq, blob: b64uEncode(c.blob) })),
      cursor: page.length ? page[page.length - 1].seq : since,
      latest: ctx.store.latest(), more, epoch: currentEpoch(state), logLength: state.length, head: hex(state.head),
    });
  }

  if (sub === '/changes' && req.method === 'POST') {
    const w = ctx.pushBucket.take(1, now);
    if (w) return rateLimited(w);
    let j: any;
    try { j = JSON.parse(new TextDecoder().decode(body)); } catch { return E(400, 'bad_json'); }
    if (!Array.isArray(j?.changes) || j.changes.length === 0) return E(400, 'no_changes');
    if (j.changes.length > LIMITS2.maxChangesPerPush) return E(413, 'too_many_changes');
    const items: ChangeInsert[] = [];
    let bytes = 0;
    const epoch = currentEpoch(state);
    for (const s of j.changes) {
      const blob = typeof s === 'string' ? b64uDecode(s) : null;
      if (!blob) return E(400, 'bad_encoding');
      if (blob.length > MAX_BUCKET) return E(413, 'change_too_large');
      const h = parseEnvelope(blob);
      if (!h) return E(400, 'bad_envelope');
      if (h.device !== member.id) return E(403, 'device_mismatch');
      if (h.epoch !== epoch) return J({ error: 'stale_epoch', epoch, logLength: state.length }, 409);
      if (!(await verifyEnvelopeSig(ctx.crypto, unhex(ctx.gid), member.ed, blob))) return E(403, 'bad_signature');
      items.push({ device: h.device, epoch: h.epoch, index: h.index, kind: h.kind, day: dayOf(now), blob });
      bytes += blob.length;
    }
    const u = ctx.store.usage();
    if (u.bytes + bytes > LIMITS2.groupQuotaBytes || u.count + items.length > LIMITS2.groupQuotaCount) return E(507, 'group_quota_exceeded');
    const results = ctx.store.insert(items);
    const fresh: ChangeRow[] = [];
    results.forEach((r, i) => { if (!r.duplicate) fresh.push({ seq: r.seq, blob: items[i].blob }); });
    if (fresh.length) ctx.broadcast(fresh);
    ctx.store.setLastWriteDay(dayOf(now));
    return J({ results: results.map((r) => (r.duplicate ? { seq: r.seq, duplicate: true } : { seq: r.seq })), cursor: ctx.store.latest(), count: ctx.store.usage().count });
  }

  if (sub === '/compact' && req.method === 'POST') {
    const w = ctx.pushBucket.take(1, now);
    if (w) return rateLimited(w);
    let j: any;
    try { j = JSON.parse(new TextDecoder().decode(body)); } catch { return E(400, 'bad_json'); }
    const upto = j?.upto;
    if (!Number.isSafeInteger(upto) || upto < 0) return E(400, 'bad_request');
    // History may only be dropped when a snapshot newer than the cut exists, so state is never lost.
    if (!ctx.store.hasSnapshotAfter(upto)) return J({ error: 'no_snapshot' }, 409);
    return J({ deleted: ctx.store.compact(upto) });
  }

  if (sub === '' && req.method === 'DELETE') {
    ctx.store.clearAll();
    ctx.onDeleted?.();
    return J({ deleted: true });
  }

  return E(404, 'not_found');
}

// ---------- pairing mailbox ----------
export interface PairStore {
  get(slot: PairSlot): { blob: Uint8Array; at: number } | null;
  /** Write-once. Returns false if the slot already holds a value. */
  put(slot: PairSlot, blob: Uint8Array, at: number): boolean;
  firstAt(): number | null;
  clear(): void;
}

/**
 * One-time pairing mailbox: PUT/GET /v2/pair/{pid}/{offer|join|welcome}. pid is 128 random bits derived from the
 * pairing secret shown as a QR code / 24 words; slots hold ciphertext only, are write-once and expire after 10 min.
 */
export async function handlePair(req: Request, slot: string, store: PairStore, now: number): Promise<Response> {
  if (req.method === 'OPTIONS') return new Response(null, { status: 204, headers: corsHeaders2() });
  if (!(PAIR_SLOTS as readonly string[]).includes(slot)) return E(404, 'not_found');
  const first = store.firstAt();
  if (first !== null && now - first > LIMITS2.pairTtlMs) { store.clear(); }
  if (req.method === 'GET') {
    const v = store.get(slot as PairSlot);
    return v ? J({ blob: b64uEncode(v.blob) }) : E(404, 'empty');
  }
  if (req.method === 'PUT') {
    const body = await readBody(req, 4096);
    if (body instanceof Response) return body;
    let blob: Uint8Array | null = null;
    try { const j = JSON.parse(new TextDecoder().decode(body)); blob = typeof j?.blob === 'string' ? b64uDecode(j.blob) : null; } catch { /* */ }
    if (!blob || blob.length < 16 || blob.length > LIMITS2.pairMaxBlob) return E(400, 'bad_blob');
    if (!store.put(slot as PairSlot, blob, now)) return E(409, 'slot_taken');
    return J({ ok: true });
  }
  return E(405, 'method_not_allowed');
}

/**
 * v1 gate: 'readwrite' (legacy), 'readonly' (transition: reads only), 'off'.
 * In 'readonly' a v1 WRITE answers 503 `v1_read_only` + Retry-After (retryable): the Android 1.7.0 client keeps its
 * queued edits on 503/429 but DROPS them on any other 4xx (measured with a test probe), so 410 would silently lose
 * edits. 410 `v1_retired` is only used once v1 is finished (past V1_READONLY_UNTIL, or mode 'off').
 */
export const V1_RETRY_AFTER_SECONDS = 900;
export type V1Gate = { ok: true } | { ok: false; code: 'v1_read_only' | 'v1_retired'; status: 503 | 410; retryAfter?: number };
export function v1Allowed(mode: string, until: string | undefined, method: string, now: number): V1Gate {
  if (mode === 'readwrite') return { ok: true };
  if (mode === 'readonly') {
    if (until) { const t = Date.parse(until); if (Number.isFinite(t) && now > t) return { ok: false, code: 'v1_retired', status: 410 }; }
    return method === 'GET' || method === 'HEAD' || method === 'OPTIONS' ? { ok: true } : { ok: false, code: 'v1_read_only', status: 503, retryAfter: V1_RETRY_AFTER_SECONDS };
  }
  return { ok: false, code: 'v1_retired', status: 410 };
}

/** In-memory store (tests and as a reference for self-host). */
export class MemoryGroupStore implements GroupStoreV2 {
  private log: Array<{ raw: Uint8Array; hash: Uint8Array }> = [];
  private rows: Array<{ seq: number; device: string; epoch: number; index: number; kind: number; day: number; blob: Uint8Array }> = [];
  private seq = 0;
  private nonces = new Map<string, number>();
  private lwd: number | null = null;
  logLength() { return this.log.length; }
  logHead() { return this.log.length ? this.log[this.log.length - 1].hash : null; }
  logLast() { return this.log.length ? this.log[this.log.length - 1].raw : null; }
  logEntries(from: number, limit: number) { return this.log.slice(from, from + limit).map((e) => e.raw); }
  logAppend(raw: Uint8Array, hash: Uint8Array) { this.log.push({ raw, hash }); }
  insert(items: ChangeInsert[]) {
    return items.map((it) => {
      const ex = this.rows.find((r) => r.device === it.device && r.epoch === it.epoch && r.index === it.index);
      if (ex) return { seq: ex.seq, duplicate: true };
      this.rows.push({ seq: ++this.seq, ...it });
      return { seq: this.seq, duplicate: false };
    });
  }
  since(since: number, limit: number) { return this.rows.filter((r) => r.seq > since).slice(0, limit).map((r) => ({ seq: r.seq, blob: r.blob })); }
  latest() { return this.seq; }
  usage() { return { count: this.rows.length, bytes: this.rows.reduce((n, r) => n + r.blob.length, 0) }; }
  nonceUsed(n: string, now: number) { if (this.nonces.has(n)) return true; this.nonces.set(n, now + LIMITS2.nonceTtlMs); return false; }
  pruneNonces(now: number) { for (const [k, v] of this.nonces) if (v < now) this.nonces.delete(k); }
  compact(upto: number) { const n = this.rows.length; this.rows = this.rows.filter((r) => r.seq > upto); return n - this.rows.length; }
  hasSnapshotAfter(seq: number) { return this.rows.some((r) => r.seq > seq && r.kind === Kind.Snapshot); }
  pruneOld(nowDay: number, retention: number) {
    const lastSnap = Math.max(0, ...this.rows.filter((r) => r.kind === Kind.Snapshot).map((r) => r.seq));
    const n = this.rows.length;
    this.rows = this.rows.filter((r) => !(r.day < nowDay - retention && r.seq < lastSnap));
    return n - this.rows.length;
  }
  lastWriteDay() { return this.lwd; }
  setLastWriteDay(d: number) { this.lwd = d; }
  clearAll() { this.log = []; this.rows = []; this.nonces.clear(); this.lwd = null; }
}

export class MemoryPairStore implements PairStore {
  private slots = new Map<PairSlot, { blob: Uint8Array; at: number }>();
  get(s: PairSlot) { return this.slots.get(s) ?? null; }
  put(s: PairSlot, blob: Uint8Array, at: number) { if (this.slots.has(s)) return false; this.slots.set(s, { blob, at }); return true; }
  firstAt() { let m: number | null = null; for (const v of this.slots.values()) if (m === null || v.at < m) m = v.at; return m; }
  clear() { this.slots.clear(); }
}

/** Inactivity retention decision shared by the Durable Object alarm and the self-host timer. */
export function retentionAction(store: GroupStoreV2, now: number, retentionDays: number): 'cleared' | 'pruned' | 'idle' {
  const lw = store.lastWriteDay();
  const day = dayOf(now);
  if (lw !== null && day - lw > retentionDays) { store.clearAll(); return 'cleared'; }
  return store.pruneOld(day, retentionDays) > 0 ? 'pruned' : 'idle';
}
