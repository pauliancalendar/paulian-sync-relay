import { describe, expect, it } from 'vitest';
import { readFileSync } from 'node:fs';
import { MemoryGroupStore, MemoryPairStore, handlePair, retentionAction, v1Allowed, LIMITS2, RELAY_VERSION, healthResponse2 } from '../src/core2';
import { Kind, MIN_BUCKET, bucketFor, isBucketSize, padInner, unpadInner, InnerType, ENVELOPE_OVERHEAD, MAX_PAYLOAD, canonicalQuery, parseAuth } from '../src/proto2';

const row = (day: number, kind: number, i: number) => ({ device: 'd', epoch: 0, index: i, kind, day, blob: new Uint8Array(4096) });

describe('retention', () => {
  it('prunes only history older than the retention that is covered by a newer snapshot', () => {
    const s = new MemoryGroupStore();
    s.insert([row(100, Kind.Update, 0), row(100, Kind.Update, 1), row(100, Kind.Snapshot, 2), row(200, Kind.Update, 3)]);
    s.setLastWriteDay(200);
    // nothing older than 90 days before day 150
    expect(retentionAction(s, 150 * 86_400_000, 90)).toBe('idle');
    // day 250: rows on day 100 are older than 90 days, but the snapshot itself (seq 3) is not covered by a newer snapshot
    expect(retentionAction(s, 250 * 86_400_000, 90)).toBe('pruned');
    expect(s.since(0, 10).map((r) => r.seq)).toEqual([3, 4]);
  });
  it('keeps old history when no newer snapshot exists (never loses the only state)', () => {
    const s = new MemoryGroupStore();
    s.insert([row(1, Kind.Update, 0), row(1, Kind.Update, 1)]);
    s.setLastWriteDay(1);
    expect(retentionAction(s, 60 * 86_400_000, 90)).toBe('idle');
    expect(s.usage().count).toBe(2);
  });
  it('deletes a whole group after the inactivity period', () => {
    const s = new MemoryGroupStore();
    s.insert([row(1, Kind.Update, 0)]);
    s.setLastWriteDay(1);
    expect(retentionAction(s, 100 * 86_400_000, 90)).toBe('cleared');
    expect(s.usage().count).toBe(0);
    expect(s.logLength()).toBe(0);
  });
  it('default is 90 days', () => expect(LIMITS2.retentionDays).toBe(90));
});

describe('v1 gate', () => {
  const now = Date.parse('2026-12-01T00:00:00Z');
  it('readwrite allows everything', () => expect(v1Allowed('readwrite', undefined, 'POST', now).ok).toBe(true));
  it('readonly allows reads until the date and never writes', () => {
    expect(v1Allowed('readonly', '2027-02-01T00:00:00Z', 'GET', now).ok).toBe(true);
    expect(v1Allowed('readonly', '2027-02-01T00:00:00Z', 'POST', now)).toEqual({ ok: false, code: 'v1_read_only', status: 503, retryAfter: 900 });
    expect(v1Allowed('readonly', '2027-02-01T00:00:00Z', 'DELETE', now)).toEqual({ ok: false, code: 'v1_read_only', status: 503, retryAfter: 900 });
    expect(v1Allowed('readonly', '2026-11-01T00:00:00Z', 'GET', now)).toEqual({ ok: false, code: 'v1_retired', status: 410 });
  });
  it('off refuses everything', () => expect(v1Allowed('off', undefined, 'GET', now).ok).toBe(false));
});

describe('padding and framing', () => {
  it('buckets are powers of two from 4 KiB and hide the payload size', () => {
    expect(bucketFor(0)).toBe(MIN_BUCKET);
    expect(bucketFor(100)).toBe(4096);
    expect(bucketFor(4096 - ENVELOPE_OVERHEAD - 5)).toBe(4096);
    expect(bucketFor(4096 - ENVELOPE_OVERHEAD - 4)).toBe(8192);
    expect(bucketFor(MAX_PAYLOAD)).toBe(1 << 20);
    expect(bucketFor(MAX_PAYLOAD + 1)).toBeNull();
    for (const n of [4096, 8192, 1 << 20]) expect(isBucketSize(n)).toBe(true);
    for (const n of [0, 4095, 4097, 12288, 2048, 1 << 21]) expect(isBucketSize(n)).toBe(false);
  });
  it('inner padding round-trips and rejects non-canonical padding', () => {
    const p = new Uint8Array([1, 2, 3]);
    const inner = padInner(InnerType.Yjs, p, 4096);
    expect(inner.length).toBe(4096 - ENVELOPE_OVERHEAD);
    expect(unpadInner(inner)).toEqual({ type: InnerType.Yjs, payload: p });
    inner[inner.length - 1] = 1;
    expect(unpadInner(inner)).toBeNull();
  });
  it('canonical query is sorted and auth header parsing is strict', () => {
    expect(canonicalQuery('?b=2&a=1')).toBe('a=1&b=2');
    expect(canonicalQuery('')).toBe('');
    expect(parseAuth('PCS2 d=zz')).toBeNull();
  });
});

describe('pairing mailbox TTL', () => {
  it('slots expire after 10 minutes', async () => {
    const st = new MemoryPairStore();
    const put = (now: number) => handlePair(new Request('http://x/v2/pair/p/offer', { method: 'PUT', body: JSON.stringify({ blob: 'AAAAAAAAAAAAAAAAAAAAAA' }) }), 'offer', st, now);
    expect((await put(0)).status).toBe(200);
    expect((await handlePair(new Request('http://x/v2/pair/p/offer'), 'offer', st, 5 * 60_000)).status).toBe(200);
    expect((await handlePair(new Request('http://x/v2/pair/p/offer'), 'offer', st, 11 * 60_000)).status).toBe(404);
  });
});

describe('relay version', () => {
  it('RELAY_VERSION is semver and equals package.json (so the apps and UPDATE.md agree)', () => {
    expect(RELAY_VERSION).toMatch(/^\d+\.\d+\.\d+$/);
    expect(JSON.parse(readFileSync(new URL('../package.json', import.meta.url), 'utf-8')).version).toBe(RELAY_VERSION);
  });
  it('health reports relayVersion next to protocol', async () => {
    expect(await healthResponse2('cloudflare-worker', 'off').json()).toMatchObject({ ok: true, service: 'paulian-sync-relay', relayVersion: RELAY_VERSION, protocol: 2, versions: [2] });
  });
});
