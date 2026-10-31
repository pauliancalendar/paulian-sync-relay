/**
 * Paulian Sync relay protocol core (v1). Platform-neutral: uses only WebCrypto and the
 * Fetch API Request/Response, so the same file runs in Cloudflare Workers and Node 22+.
 *
 * CANONICAL COPY: relay/src/core.ts. relay-selfhost/src/core.ts is a vendored copy
 * (scripts/vendor-relay-core.sh); never edit the copy by hand.
 *
 * The relay never sees plaintext. It stores opaque signed envelopes per group and checks:
 *   - group ID == SHA-256("paulian-sync/v1/group-id" || pk)  (pk sent by the client)
 *   - every envelope carries a valid Ed25519 signature by pk (rejects injected blobs)
 *   - (deviceId, counter) is unique per group (rejects replayed blobs)
 *   - size caps, per-group quota and rate limits
 */

export const PROTOCOL_VERSION = 1;
export const LIMITS = {
  maxBlobBytes: 1024 * 1024,          // one envelope (decoded)
  maxBodyBytes: 3 * 1024 * 1024,      // one HTTP request body (base64url JSON)
  maxChangesPerPush: 100,
  maxFetchLimit: 500,
  groupQuotaBytes: 64 * 1024 * 1024,  // stored per group
  groupQuotaCount: 50_000,
  maxSocketsPerGroup: 16,
  signedRequestSkewMs: 10 * 60 * 1000,
  pushRate: { capacity: 60, refillPerSec: 1 },    // per group: burst 60, then 1 req/s
  readRate: { capacity: 120, refillPerSec: 4 },
};

const HEADER_BYTES = 38;
const NONCE_BYTES = 24;
const SIG_BYTES = 64;
const MIN_ENVELOPE = HEADER_BYTES + NONCE_BYTES + 16 + SIG_BYTES;
const enc = new TextEncoder();
const SIG_DOMAIN = enc.encode('paulian-sync/v1/sig');
const GID_DOMAIN = enc.encode('paulian-sync/v1/group-id');

export interface StoredChange { seq: number; blob: Uint8Array }
export interface InsertItem { device: string; counter: number; blob: Uint8Array }

/** Synchronous storage for ONE group (SQLite in both implementations). */
export interface GroupStore {
  insert(items: InsertItem[]): Array<{ seq: number; duplicate: boolean }>;
  since(since: number, limit: number): StoredChange[];
  latest(): number;
  usage(): { count: number; bytes: number };
  compact(upto: number): number;
  clear(): number;
}

export class TokenBucket {
  private tokens: number;
  private last: number;
  constructor(private capacity: number, private refillPerSec: number, now = Date.now()) {
    this.tokens = capacity; this.last = now;
  }
  /** Returns 0 if allowed, otherwise ms to wait. */
  take(n = 1, now = Date.now()): number {
    this.tokens = Math.min(this.capacity, this.tokens + ((now - this.last) / 1000) * this.refillPerSec);
    this.last = now;
    if (this.tokens >= n) { this.tokens -= n; return 0; }
    return Math.ceil(((n - this.tokens) / this.refillPerSec) * 1000);
  }
}

export const GROUP_ID_RE = /^[0-9a-f]{64}$/;

export function corsHeaders(): Record<string, string> {
  return {
    'access-control-allow-origin': '*',
    'access-control-allow-methods': 'GET, POST, DELETE, OPTIONS',
    'access-control-allow-headers': 'content-type',
    'access-control-max-age': '86400',
  };
}

export function json(body: unknown, status = 200, extra: Record<string, string> = {}): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'content-type': 'application/json', 'cache-control': 'no-store', ...corsHeaders(), ...extra },
  });
}

export function err(status: number, code: string, extra: Record<string, string> = {}): Response {
  return json({ error: code }, status, extra);
}

export function healthResponse(impl: string): Response {
  return json({ ok: true, protocol: PROTOCOL_VERSION, impl });
}

// ---------- encoding ----------
export function b64uDecode(s: string): Uint8Array | null {
  if (typeof s !== 'string' || /[^A-Za-z0-9_-]/.test(s)) return null;
  try {
    const bin = atob(s.replace(/-/g, '+').replace(/_/g, '/') + '==='.slice((s.length + 3) % 4));
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  } catch { return null; }
}

export function b64uEncode(b: Uint8Array): string {
  let bin = '';
  for (let i = 0; i < b.length; i += 0x8000) bin += String.fromCharCode(...b.subarray(i, i + 0x8000));
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function hex(b: Uint8Array): string {
  let s = '';
  for (const x of b) s += x.toString(16).padStart(2, '0');
  return s;
}

function hexToBytes(s: string): Uint8Array {
  const out = new Uint8Array(s.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(s.slice(i * 2, i * 2 + 2), 16);
  return out;
}

function concat(...p: Uint8Array[]): Uint8Array {
  const o = new Uint8Array(p.reduce((n, x) => n + x.length, 0));
  let i = 0;
  for (const x of p) { o.set(x, i); i += x.length; }
  return o;
}

// ---------- crypto ----------
const bs = (u: Uint8Array) => u as unknown as BufferSource;
export async function groupIdForPk(pk: Uint8Array): Promise<string> {
  return hex(new Uint8Array(await crypto.subtle.digest('SHA-256', bs(concat(GID_DOMAIN, pk)))));
}

async function importPk(pk: Uint8Array): Promise<CryptoKey> {
  return crypto.subtle.importKey('raw', bs(pk), { name: 'Ed25519' }, false, ['verify']);
}

async function ed25519Verify(key: CryptoKey, sig: Uint8Array, msg: Uint8Array): Promise<boolean> {
  try { return await crypto.subtle.verify({ name: 'Ed25519' }, key, bs(sig), bs(msg)); } catch { return false; }
}

/** Checks that pk belongs to gid. Returns the imported key or null. */
export async function groupKey(gid: string, pkB64: unknown): Promise<CryptoKey | null> {
  const pk = typeof pkB64 === 'string' ? b64uDecode(pkB64) : null;
  if (!pk || pk.length !== 32) return null;
  if ((await groupIdForPk(pk)) !== gid) return null;
  try { return await importPk(pk); } catch { return null; }
}

export function parseEnvelopeHeader(blob: Uint8Array): { device: string; counter: number } | null {
  if (blob.length < MIN_ENVELOPE || blob.length > LIMITS.maxBlobBytes) return null;
  if (blob[0] !== 0x50 || blob[1] !== 0x43 || blob[2] !== 0x53 || blob[3] !== 0x31 || blob[4] !== 1) return null; // "PCS1" v1
  if (blob[5] !== 1 && blob[5] !== 2) return null;
  const dv = new DataView(blob.buffer, blob.byteOffset, blob.byteLength);
  const counter = dv.getBigUint64(22);
  if (counter < 1n || counter > BigInt(Number.MAX_SAFE_INTEGER)) return null;
  return { device: hex(blob.subarray(6, 22)), counter: Number(counter) };
}

export async function verifyEnvelope(gid: string, key: CryptoKey, blob: Uint8Array): Promise<boolean> {
  const body = blob.subarray(0, blob.length - SIG_BYTES);
  const sig = blob.subarray(blob.length - SIG_BYTES);
  return ed25519Verify(key, sig, concat(SIG_DOMAIN, hexToBytes(gid), body));
}

async function readJson(req: Request): Promise<any | Response> {
  const len = Number(req.headers.get('content-length') ?? '0');
  if (len > LIMITS.maxBodyBytes) return err(413, 'body_too_large');
  if (!req.body) return err(400, 'missing_body');
  const reader = req.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.length;
    if (total > LIMITS.maxBodyBytes) { try { await reader.cancel(); } catch { /* */ } return err(413, 'body_too_large'); }
    chunks.push(value);
  }
  try { return JSON.parse(new TextDecoder().decode(concat(...chunks))); } catch { return err(400, 'bad_json'); }
}

export interface GroupContext {
  gid: string;
  store: GroupStore;
  pushBucket: TokenBucket;
  readBucket: TokenBucket;
  /** Called after new changes were stored, to fan out to live sockets. */
  broadcast(changes: StoredChange[]): void;
  /** Called after the group was deleted (close sockets). */
  onDeleted?(): void;
  now?: () => number;
}

function rateLimited(ms: number): Response {
  return err(429, 'rate_limited', { 'retry-after': String(Math.max(1, Math.ceil(ms / 1000))) });
}

export function changesFrame(changes: StoredChange[]): string {
  return JSON.stringify({ type: 'changes', changes: changes.map((c) => ({ seq: c.seq, blob: b64uEncode(c.blob) })) });
}

/**
 * Handles everything under /v1/groups/{gid}/ except the WebSocket upgrade.
 * `sub` is the path after the gid: "/changes", "/compact" or "".
 */
export async function handleGroupHttp(req: Request, sub: string, ctx: GroupContext): Promise<Response> {
  const now = ctx.now?.() ?? Date.now();
  if (req.method === 'OPTIONS') return new Response(null, { status: 204, headers: corsHeaders() });

  if (sub === '/changes' && req.method === 'GET') {
    const w = ctx.readBucket.take(1, now);
    if (w) return rateLimited(w);
    const url = new URL(req.url);
    const since = Number(url.searchParams.get('since') ?? '0');
    const limit = Math.min(LIMITS.maxFetchLimit, Math.max(1, Number(url.searchParams.get('limit') ?? '200') || 200));
    if (!Number.isSafeInteger(since) || since < 0) return err(400, 'bad_since');
    const rows = ctx.store.since(since, limit + 1);
    const more = rows.length > limit;
    const page = more ? rows.slice(0, limit) : rows;
    return json({
      changes: page.map((c) => ({ seq: c.seq, blob: b64uEncode(c.blob) })),
      cursor: page.length ? page[page.length - 1].seq : Math.max(since, 0),
      latest: ctx.store.latest(),
      more,
    });
  }

  if (sub === '/changes' && req.method === 'POST') {
    const w = ctx.pushBucket.take(1, now);
    if (w) return rateLimited(w);
    const body = await readJson(req);
    if (body instanceof Response) return body;
    const key = await groupKey(ctx.gid, body?.pk);
    if (!key) return err(403, 'pk_does_not_match_group');
    if (!Array.isArray(body.changes) || body.changes.length === 0) return err(400, 'no_changes');
    if (body.changes.length > LIMITS.maxChangesPerPush) return err(413, 'too_many_changes');
    const items: InsertItem[] = [];
    let bytes = 0;
    for (const s of body.changes) {
      const blob = b64uDecode(s);
      if (!blob) return err(400, 'bad_encoding');
      if (blob.length > LIMITS.maxBlobBytes) return err(413, 'change_too_large');
      const h = parseEnvelopeHeader(blob);
      if (!h) return err(400, 'bad_envelope');
      if (!(await verifyEnvelope(ctx.gid, key, blob))) return err(403, 'bad_signature');
      items.push({ ...h, blob });
      bytes += blob.length;
    }
    const u = ctx.store.usage();
    if (u.bytes + bytes > LIMITS.groupQuotaBytes || u.count + items.length > LIMITS.groupQuotaCount) {
      return err(507, 'group_quota_exceeded');
    }
    const results = ctx.store.insert(items);
    const fresh: StoredChange[] = [];
    results.forEach((r, i) => { if (!r.duplicate) fresh.push({ seq: r.seq, blob: items[i].blob }); });
    if (fresh.length) ctx.broadcast(fresh);
    const after = ctx.store.usage();
    return json({ results: results.map((r) => (r.duplicate ? { seq: r.seq, duplicate: true } : { seq: r.seq })), cursor: ctx.store.latest(), count: after.count });
  }

  if (sub === '/compact' && req.method === 'POST') {
    const w = ctx.pushBucket.take(1, now);
    if (w) return rateLimited(w);
    const body = await readJson(req);
    if (body instanceof Response) return body;
    const key = await groupKey(ctx.gid, body?.pk);
    if (!key) return err(403, 'pk_does_not_match_group');
    const { upto, ts } = body;
    if (!Number.isSafeInteger(upto) || upto < 0 || !Number.isSafeInteger(ts)) return err(400, 'bad_request');
    if (Math.abs(now - ts) > LIMITS.signedRequestSkewMs) return err(400, 'stale_request');
    const sig = b64uDecode(body.sig);
    if (!sig || !(await ed25519Verify(key, sig, enc.encode(`paulian-sync/v1/compact:${ctx.gid}:${upto}:${ts}`)))) return err(403, 'bad_signature');
    // Never delete the newest change, so a snapshot always remains.
    const safeUpto = Math.min(upto, ctx.store.latest() - 1);
    return json({ deleted: safeUpto > 0 ? ctx.store.compact(safeUpto) : 0 });
  }

  if (sub === '' && req.method === 'DELETE') {
    const body = await readJson(req);
    if (body instanceof Response) return body;
    const key = await groupKey(ctx.gid, body?.pk);
    if (!key) return err(403, 'pk_does_not_match_group');
    const { ts } = body;
    if (!Number.isSafeInteger(ts) || Math.abs(now - ts) > LIMITS.signedRequestSkewMs) return err(400, 'stale_request');
    const sig = b64uDecode(body.sig);
    if (!sig || !(await ed25519Verify(key, sig, enc.encode(`paulian-sync/v1/delete:${ctx.gid}:${ts}`)))) return err(403, 'bad_signature');
    ctx.store.clear();
    ctx.onDeleted?.();
    return json({ deleted: true });
  }

  return err(404, 'not_found');
}

/** Parses "/v1/groups/{gid}{sub}". Returns null when the path is not a group path. */
export function parseGroupPath(pathname: string): { gid: string; sub: string } | null {
  const m = /^\/v1\/groups\/([^/]+)(\/[a-z]+)?\/?$/.exec(pathname);
  if (!m) return null;
  return { gid: m[1], sub: m[2] ?? '' };
}

/** Backlog pages for a newly connected socket. */
export function backlogFrames(store: GroupStore, since: number, maxFrames = 20, pageSize = 100): string[] {
  const frames: string[] = [];
  let cur = since;
  for (let i = 0; i < maxFrames; i++) {
    const rows = store.since(cur, pageSize);
    if (!rows.length) break;
    frames.push(changesFrame(rows));
    cur = rows[rows.length - 1].seq;
    if (rows.length < pageSize) break;
  }
  return frames;
}
