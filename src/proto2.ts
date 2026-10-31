/**
 * Paulian Sync protocol v2: pure wire-format code shared (copied, never symlinked) by the relay and
 * the desktop clients. No I/O. Crypto is injected so it runs on WebCrypto (relay) and libsodium (clients).
 *
 * CANONICAL COPY: paulian_sync_relay/relay/src/proto2.ts. The desktop repos hold byte-identical copies
 * at project/src/desktop/sync/core2/proto2.ts (check with scripts/check-proto2-copies.sh).
 * See docs/PROTOCOL_V2.md for the normative description.
 */
export const PROTO_VERSION = 2;
const te = new TextEncoder();
export const utf8 = (s: string) => te.encode(s);

export const MIN_BUCKET = 4096;
export const MAX_BUCKET = 1 << 20;
export const MAX_MEMBERS = 16;
export const HEADER_BYTES = 46;
export const NONCE_BYTES = 24;
export const TAG_BYTES = 16;
export const SIG_BYTES = 64;
/** Envelope overhead: header + nonce + tag + signature. */
export const ENVELOPE_OVERHEAD = HEADER_BYTES + NONCE_BYTES + TAG_BYTES + SIG_BYTES; // 150
/** Inner plaintext header: type u8 + payload length u32. */
export const INNER_HEADER = 5;
export const PKG_CT_BYTES = 80; // crypto_box(epochKey 32 || groupRoot 32) = 64 + 16 MAC
export const REQ_SKEW_MS = 5 * 60 * 1000;

export const DOM = {
  req: 'PCS2-REQ',
  env: 'paulian-sync/v2/env',
  log: 'paulian-sync/v2/log',
  aad: 'paulian-sync/v2/aad',
  deviceId: 'paulian-sync/v2/device-id',
} as const;

export enum LogType { Genesis = 0, Add = 1, Remove = 2, Rotate = 3 }
export enum Kind { Update = 1, Snapshot = 2 }
export enum InnerType { Yjs = 0, Snapshot = 1, Cover = 2 }

export interface Crypto2 {
  sha256(b: Uint8Array): Promise<Uint8Array>;
  verify(pk: Uint8Array, msg: Uint8Array, sig: Uint8Array): Promise<boolean>;
}

// ---------- bytes ----------
export function concat(...p: Uint8Array[]): Uint8Array {
  const o = new Uint8Array(p.reduce((n, x) => n + x.length, 0));
  let i = 0;
  for (const x of p) { o.set(x, i); i += x.length; }
  return o;
}
export function hex(b: Uint8Array): string { let s = ''; for (const x of b) s += x.toString(16).padStart(2, '0'); return s; }
export function unhex(s: string): Uint8Array {
  if (typeof s !== 'string' || s.length % 2 || /[^0-9a-f]/.test(s)) throw new Error('bad hex');
  const o = new Uint8Array(s.length / 2);
  for (let i = 0; i < o.length; i++) o[i] = parseInt(s.slice(i * 2, i * 2 + 2), 16);
  return o;
}
export function eq(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let d = 0;
  for (let i = 0; i < a.length; i++) d |= a[i] ^ b[i];
  return d === 0;
}
export function u32(n: number): Uint8Array { const o = new Uint8Array(4); new DataView(o.buffer).setUint32(0, n >>> 0); return o; }
export function b64uEncode(b: Uint8Array): string {
  let bin = '';
  for (let i = 0; i < b.length; i += 0x8000) bin += String.fromCharCode(...b.subarray(i, i + 0x8000));
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
export function b64uDecode(s: string): Uint8Array | null {
  if (typeof s !== 'string' || /[^A-Za-z0-9_-]/.test(s)) return null;
  try {
    const bin = atob(s.replace(/-/g, '+').replace(/_/g, '/') + '==='.slice((s.length + 3) % 4));
    const o = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) o[i] = bin.charCodeAt(i);
    return o;
  } catch { return null; }
}

// ---------- padding ----------
/** Smallest power-of-two bucket (>= 4 KiB) that holds an envelope carrying `payloadLen` bytes, or null if > 1 MiB. */
export function bucketFor(payloadLen: number): number | null {
  const need = ENVELOPE_OVERHEAD + INNER_HEADER + payloadLen;
  let b = MIN_BUCKET;
  while (b < need) b *= 2;
  return b > MAX_BUCKET ? null : b;
}
export function isBucketSize(n: number): boolean {
  return Number.isInteger(n) && n >= MIN_BUCKET && n <= MAX_BUCKET && (n & (n - 1)) === 0;
}
/** Largest payload that fits one envelope. */
export const MAX_PAYLOAD = MAX_BUCKET - ENVELOPE_OVERHEAD - INNER_HEADER;

// ---------- ids ----------
export async function deviceIdFor(c: Crypto2, gid: Uint8Array, edPk: Uint8Array): Promise<Uint8Array> {
  return (await c.sha256(concat(utf8(DOM.deviceId), gid, edPk))).subarray(0, 16);
}

// ---------- signed requests ----------
export interface AuthHeader { d: string; t: number; n: string; s: string }
export function formatAuth(a: AuthHeader): string { return `PCS2 d=${a.d},t=${a.t},n=${a.n},s=${a.s}`; }
export function parseAuth(h: string | null): AuthHeader | null {
  if (!h || h.length > 400) return null;
  const m = /^PCS2 d=([0-9a-f]{32}),t=(\d{1,16}),n=([A-Za-z0-9_-]{22}),s=([A-Za-z0-9_-]{86})$/.exec(h);
  if (!m) return null;
  return { d: m[1], t: Number(m[2]), n: m[3], s: m[4] };
}
export function canonicalQuery(search: string): string {
  const q = search.startsWith('?') ? search.slice(1) : search;
  if (!q) return '';
  return q.split('&').filter(Boolean).sort().join('&');
}
/** Canonical string a device signs for every relay request. */
export async function canonicalRequest(c: Crypto2, method: string, path: string, search: string, body: Uint8Array, t: number, n: string, d: string): Promise<Uint8Array> {
  const bh = hex(await c.sha256(body));
  return utf8([DOM.req, method, path, canonicalQuery(search), bh, String(t), n, d].join('\n'));
}

// ---------- envelope ----------
export interface EnvHeader { kind: Kind; epoch: number; device: string; index: number; prev: Uint8Array }
export function parseEnvelope(blob: Uint8Array): (EnvHeader & { size: number }) | null {
  if (!isBucketSize(blob.length)) return null;
  if (blob[0] !== 0x50 || blob[1] !== 0x43 || blob[2] !== 0x53 || blob[3] !== 0x32 || blob[4] !== 2) return null; // "PCS2" v2
  const kind = blob[5];
  if (kind !== Kind.Update && kind !== Kind.Snapshot) return null;
  const dv = new DataView(blob.buffer, blob.byteOffset, blob.byteLength);
  return { kind, epoch: dv.getUint32(6), device: hex(blob.subarray(10, 26)), index: dv.getUint32(26), prev: blob.subarray(30, 46), size: blob.length };
}
export function encodeEnvHeader(h: EnvHeader): Uint8Array {
  const o = new Uint8Array(HEADER_BYTES);
  o.set([0x50, 0x43, 0x53, 0x32, 2, h.kind], 0);
  const dv = new DataView(o.buffer);
  dv.setUint32(6, h.epoch);
  o.set(unhex(h.device), 10);
  dv.setUint32(26, h.index);
  if (h.prev.length !== 16) throw new Error('prev must be 16 bytes');
  o.set(h.prev, 30);
  return o;
}
export function envSignedMessage(gid: Uint8Array, bodyWithoutSig: Uint8Array): Uint8Array { return concat(utf8(DOM.env), gid, bodyWithoutSig); }
export function envAad(gid: Uint8Array, header: Uint8Array, epochHead: Uint8Array): Uint8Array { return concat(utf8(DOM.aad), gid, header, epochHead); }
export async function verifyEnvelopeSig(c: Crypto2, gid: Uint8Array, edPk: Uint8Array, blob: Uint8Array): Promise<boolean> {
  return c.verify(edPk, envSignedMessage(gid, blob.subarray(0, blob.length - SIG_BYTES)), blob.subarray(blob.length - SIG_BYTES));
}
/** First 16 bytes of SHA-256(envelope): the `prev` value of the same device's next envelope in the same epoch. */
export async function envelopeLinkHash(c: Crypto2, blob: Uint8Array): Promise<Uint8Array> { return (await c.sha256(blob)).subarray(0, 16); }

// ---------- membership log ----------
export interface Member { id: string; ed: Uint8Array; x: Uint8Array }
export interface Pkg { to: string; nonce: Uint8Array; ct: Uint8Array }
export interface LogEntry {
  type: LogType; prev: Uint8Array; index: number; day: number; signer: string;
  members: Member[]; pkgs: Pkg[]; sig: Uint8Array; body: Uint8Array; raw: Uint8Array;
}

export function encodeLogBody(e: Omit<LogEntry, 'sig' | 'body' | 'raw'>): Uint8Array {
  const parts: Uint8Array[] = [new Uint8Array([0x50, 0x43, 0x4d, 0x32, 2, e.type]), e.prev, u32(e.index), u32(e.day), unhex(e.signer), new Uint8Array([e.members.length])];
  for (const m of e.members) parts.push(unhex(m.id), m.ed, m.x);
  parts.push(new Uint8Array([e.pkgs.length]));
  for (const p of e.pkgs) parts.push(unhex(p.to), p.nonce, new Uint8Array([p.ct.length >> 8, p.ct.length & 255]), p.ct);
  return concat(...parts);
}
export function logSignedMessage(gid: Uint8Array, body: Uint8Array): Uint8Array { return concat(utf8(DOM.log), gid, body); }

export function parseLogEntry(raw: Uint8Array): LogEntry | null {
  try {
    if (raw.length < 6 + 32 + 8 + 16 + 1 + 80 + 1 + SIG_BYTES || raw.length > 8192) return null;
    if (raw[0] !== 0x50 || raw[1] !== 0x43 || raw[2] !== 0x4d || raw[3] !== 0x32 || raw[4] !== 2) return null;
    const type = raw[5];
    if (type > 3) return null;
    const dv = new DataView(raw.buffer, raw.byteOffset, raw.byteLength);
    const index = dv.getUint32(38);
    const day = dv.getUint32(42);
    const signer = hex(raw.subarray(46, 62));
    const mc = raw[62];
    if (mc < 1 || mc > MAX_MEMBERS) return null;
    let o = 63;
    const members: Member[] = [];
    for (let i = 0; i < mc; i++) {
      members.push({ id: hex(raw.subarray(o, o + 16)), ed: raw.slice(o + 16, o + 48), x: raw.slice(o + 48, o + 80) });
      o += 80;
    }
    const pc = raw[o++];
    if (pc > MAX_MEMBERS) return null;
    const pkgs: Pkg[] = [];
    for (let i = 0; i < pc; i++) {
      const to = hex(raw.subarray(o, o + 16));
      const nonce = raw.slice(o + 16, o + 40);
      const len = dv.getUint16(o + 40);
      if (len !== PKG_CT_BYTES) return null;
      pkgs.push({ to, nonce, ct: raw.slice(o + 42, o + 42 + len) });
      o += 42 + len;
    }
    if (raw.length !== o + SIG_BYTES) return null;
    return { type, prev: raw.slice(6, 38), index, day, signer, members, pkgs, sig: raw.slice(o), body: raw.slice(0, o), raw: raw.slice() };
  } catch { return null; }
}

export interface GroupState {
  /** Number of entries applied; the next entry must have index === length. */
  length: number;
  /** Hash of the last entry (zeros before the genesis). */
  head: Uint8Array;
  members: Member[];
  /** Day (unix seconds, floored) of the entry that started the current epoch. */
  epochDay: number;
}
export const ZERO32 = new Uint8Array(32);
export const emptyState = (): GroupState => ({ length: 0, head: ZERO32, members: [], epochDay: 0 });
export const currentEpoch = (s: GroupState) => s.length - 1;

/**
 * Validates one entry against the state it extends and returns the new state, or an error code.
 * Rules (both relay and clients enforce them): chain by hash and index; signer is a current member
 * (genesis: the only member); member ids derive from (gid, ed25519 public key); members sorted by id;
 * add => strict superset, remove => strict subset (never empty), rotate => same set; every member except
 * the signer gets exactly one key package; day does not go backwards.
 */
export async function applyLogEntry(c: Crypto2, gid: Uint8Array, s: GroupState, raw: Uint8Array): Promise<{ ok: true; state: GroupState; entry: LogEntry } | { ok: false; error: string }> {
  const e = parseLogEntry(raw);
  if (!e) return { ok: false, error: 'bad_entry' };
  if (e.index !== s.length) return { ok: false, error: 'bad_index' };
  if (!eq(e.prev, s.head)) return { ok: false, error: 'bad_prev' };
  if (e.day % 86400 !== 0 || e.day < s.epochDay) return { ok: false, error: 'bad_day' };
  for (let i = 0; i < e.members.length; i++) {
    const m = e.members[i];
    if (m.ed.length !== 32 || m.x.length !== 32) return { ok: false, error: 'bad_member' };
    if (i > 0 && !(e.members[i - 1].id < m.id)) return { ok: false, error: 'members_not_sorted' };
    if (hex(await deviceIdFor(c, gid, m.ed)) !== m.id) return { ok: false, error: 'bad_device_id' };
  }
  const ids = new Set(e.members.map((m) => m.id));
  if (e.type === LogType.Genesis) {
    if (s.length !== 0 || e.members.length !== 1 || e.members[0].id !== e.signer) return { ok: false, error: 'bad_genesis' };
    if (e.pkgs.length !== 0) return { ok: false, error: 'bad_packages' };
  } else {
    if (s.length === 0) return { ok: false, error: 'no_genesis' };
    const prevIds = new Set(s.members.map((m) => m.id));
    if (!prevIds.has(e.signer)) return { ok: false, error: 'signer_not_member' };
    const prevM = new Map(s.members.map((m) => [m.id, m]));
    for (const m of e.members) {
      const p = prevM.get(m.id);
      if (p && (!eq(p.ed, m.ed) || !eq(p.x, m.x))) return { ok: false, error: 'member_key_changed' };
    }
    const added = e.members.filter((m) => !prevIds.has(m.id)).length;
    const removed = s.members.filter((m) => !ids.has(m.id)).length;
    if (e.type === LogType.Add && !(added > 0 && removed === 0)) return { ok: false, error: 'bad_add' };
    if (e.type === LogType.Remove && !(removed > 0 && added === 0)) return { ok: false, error: 'bad_remove' };
    if (e.type === LogType.Rotate && !(added === 0 && removed === 0)) return { ok: false, error: 'bad_rotate' };
    const want = new Set(e.members.filter((m) => m.id !== e.signer).map((m) => m.id));
    if (e.pkgs.length !== want.size) return { ok: false, error: 'bad_packages' };
    const seen = new Set<string>();
    for (const p of e.pkgs) {
      if (!want.has(p.to) || seen.has(p.to) || p.nonce.length !== NONCE_BYTES) return { ok: false, error: 'bad_packages' };
      seen.add(p.to);
    }
  }
  const signerM = e.type === LogType.Genesis ? e.members[0] : s.members.find((m) => m.id === e.signer)!;
  if (!(await c.verify(signerM.ed, logSignedMessage(gid, e.body), e.sig))) return { ok: false, error: 'bad_signature' };
  const head = await c.sha256(e.raw);
  return { ok: true, entry: e, state: { length: s.length + 1, head, members: e.members, epochDay: e.day } };
}

// ---------- ratchet (pure HMAC-SHA256; hmac injected so it runs anywhere) ----------
export type Hmac = (key: Uint8Array, data: Uint8Array) => Uint8Array;
export const CHAIN_MSG = new Uint8Array([1]);
export const CHAIN_NEXT = new Uint8Array([2]);

// ---------- inner plaintext ----------
export function padInner(type: InnerType, payload: Uint8Array, bucket: number): Uint8Array {
  const len = bucket - ENVELOPE_OVERHEAD;
  if (payload.length + INNER_HEADER > len) throw new Error('payload too large for bucket');
  const o = new Uint8Array(len);
  o[0] = type;
  new DataView(o.buffer).setUint32(1, payload.length);
  o.set(payload, INNER_HEADER);
  // Padding is always zero bytes (canonical); it is encrypted, so it leaks nothing.
  return o;
}
export function unpadInner(inner: Uint8Array): { type: InnerType; payload: Uint8Array } | null {
  if (inner.length < INNER_HEADER) return null;
  const type = inner[0];
  if (type > 2) return null;
  const n = new DataView(inner.buffer, inner.byteOffset, inner.byteLength).getUint32(1);
  if (n > inner.length - INNER_HEADER) return null;
  // Padding must be all zero (canonical form).
  for (let i = INNER_HEADER + n; i < inner.length; i++) if (inner[i] !== 0) return null;
  return { type, payload: inner.subarray(INNER_HEADER, INNER_HEADER + n) };
}

// ---------- pairing ----------
export const PAIR_SLOTS = ['offer', 'join', 'welcome'] as const;
export type PairSlot = (typeof PAIR_SLOTS)[number];
