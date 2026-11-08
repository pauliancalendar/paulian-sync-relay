/** Test-side protocol v2 client (libsodium + node:crypto). Independent of the relay code paths it exercises. */
import sodium from 'libsodium-wrappers-sumo';
import { createHash, randomBytes } from 'node:crypto';
import { LogType, Kind, encodeLogBody, logSignedMessage, encodeEnvHeader, envSignedMessage, hex, canonicalQuery, concat, utf8, HEADER_BYTES, NONCE_BYTES, SIG_BYTES, formatAuth, b64uEncode } from '../src/proto2';

export const sha = (b: Uint8Array) => new Uint8Array(createHash('sha256').update(b).digest());
export const ready = () => sodium.ready;

export interface Dev { id: string; ed: Uint8Array; edSk: Uint8Array; x: Uint8Array; index: Map<number, number> }
export interface Grp { gid: Uint8Array; gidHex: string; entries: Uint8Array[]; head: Uint8Array; members: Dev[]; length: number }

export function newDev(gid: Uint8Array): Dev {
  const kp = sodium.crypto_sign_seed_keypair(randomBytes(32));
  const id = hex(sha(concat(utf8('paulian-sync/v2/device-id'), gid, kp.publicKey)).subarray(0, 16));
  return { id, ed: kp.publicKey, edSk: kp.privateKey, x: randomBytes(32), index: new Map() };
}

export function newGrp(): { g: Grp; founder: Dev } {
  const gid = randomBytes(32);
  const founder = newDev(gid);
  return { g: { gid, gidHex: hex(gid), entries: [], head: new Uint8Array(32), members: [founder], length: 0 }, founder };
}

export function member(d: Dev) { return { id: d.id, ed: d.ed, x: d.x }; }

export function logEntry(g: Grp, signer: Dev, type: LogType, members: Dev[], opts: { day?: number; badSig?: boolean; pkgFor?: string[] } = {}): Uint8Array {
  const sorted = [...members].sort((a, b) => (a.id < b.id ? -1 : 1));
  const day = opts.day ?? Math.floor(Date.now() / 86_400_000) * 86400;
  const pkgTargets = type === LogType.Genesis ? [] : (opts.pkgFor ?? sorted.filter((m) => m.id !== signer.id).map((m) => m.id));
  const body = encodeLogBody({
    type, prev: g.head, index: g.length, day, signer: signer.id, members: sorted.map(member),
    pkgs: pkgTargets.map((to) => ({ to, nonce: randomBytes(24), ct: randomBytes(80) })),
  });
  const sig = sodium.crypto_sign_detached(logSignedMessage(g.gid, body), signer.edSk);
  if (opts.badSig) sig[0] ^= 1;
  return concat(body, sig);
}

export function commit(g: Grp, entry: Uint8Array, members: Dev[]) {
  g.entries.push(entry); g.head = sha(entry); g.length++; g.members = members;
}

export function authHeader(d: Dev, method: string, path: string, search: string, body: Uint8Array = new Uint8Array(0), over: { t?: number; n?: string } = {}): string {
  const t = over.t ?? Date.now();
  const n = over.n ?? b64uEncode(randomBytes(16));
  const msg = utf8([ 'PCS2-REQ', method, path, canonicalQuery(search), hex(sha(body)), String(t), n, d.id ].join('\n'));
  const s = b64uEncode(sodium.crypto_sign_detached(msg, d.edSk));
  return formatAuth({ d: d.id, t, n, s });
}

export function envelope(g: Grp, d: Dev, o: { epoch?: number; index?: number; bucket?: number; kind?: Kind; badSig?: boolean } = {}): Uint8Array {
  const epoch = o.epoch ?? g.length - 1;
  const index = o.index ?? (d.index.get(epoch) ?? 0);
  d.index.set(epoch, index + 1);
  const bucket = o.bucket ?? 4096;
  const header = encodeEnvHeader({ kind: o.kind ?? Kind.Update, epoch, device: d.id, index, prev: new Uint8Array(16) });
  const ct = randomBytes(bucket - HEADER_BYTES - NONCE_BYTES - SIG_BYTES);
  const body = concat(header, randomBytes(NONCE_BYTES), ct);
  const sig = sodium.crypto_sign_detached(envSignedMessage(g.gid, body), d.edSk);
  if (o.badSig) sig[0] ^= 1;
  return concat(body, sig);
}

export const b64u = b64uEncode;

export async function call(base: string, d: Dev | null, method: string, path: string, opts: { search?: string; body?: unknown; raw?: Uint8Array; hdr?: string; accessKey?: string } = {}) {
  const search = opts.search ?? '';
  const bodyBytes = opts.raw ?? (opts.body === undefined ? new Uint8Array(0) : utf8(JSON.stringify(opts.body)));
  const headers: Record<string, string> = {};
  if (bodyBytes.length) headers['content-type'] = 'application/json';
  if (opts.hdr) headers.authorization = opts.hdr;
  else if (d) headers.authorization = authHeader(d, method, path, search, bodyBytes);
  if (opts.accessKey) headers['x-paulian-relay-key'] = opts.accessKey;
  const res = await fetch(base + path + search, { method, headers, body: bodyBytes.length ? (bodyBytes as unknown as BodyInit) : undefined });
  let json: any = null;
  try { json = await res.json(); } catch { /* none */ }
  return { status: res.status, json };
}
