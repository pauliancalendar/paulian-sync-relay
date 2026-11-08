import { describe, expect, it } from 'vitest';
import { MemoryPairStore, accessSecretOk, handlePair, providedAccessSecret, RELAY_ACCESS_HEADER, webCrypto2 } from '../src/core2';
import {
  PAIR_AUTH_PK_HEADER, PAIR_AUTH_SIG_HEADER, PAIR_AUTH_TS_HEADER, REQ_SKEW_MS, b64uEncode, hex, pairAuthMessage, utf8,
} from '../src/proto2';

const BLOB = b64uEncode(new Uint8Array(32).fill(7));
const OFFER = 'http://x/v2/pair/aabbccddeeff00112233445566778899/offer';
const JOIN = 'http://x/v2/pair/aabbccddeeff00112233445566778899/join';

async function genKp(): Promise<CryptoKeyPair> {
  return crypto.subtle.generateKey({ name: 'Ed25519' }, true, ['sign', 'verify']) as Promise<CryptoKeyPair>;
}

async function signed(method: string, url: string, bodyObj: unknown | undefined, kp: CryptoKeyPair, now: number) {
  const bodyText = bodyObj === undefined ? '' : JSON.stringify(bodyObj);
  const body = utf8(bodyText);
  const hash = hex(await webCrypto2.sha256(body));
  const msg = pairAuthMessage(method, new URL(url).pathname, now, hash);
  const sig = new Uint8Array(await crypto.subtle.sign({ name: 'Ed25519' }, kp.privateKey, msg as unknown as BufferSource));
  const pk = new Uint8Array(await crypto.subtle.exportKey('raw', kp.publicKey) as ArrayBuffer);
  const headers: Record<string, string> = {
    [PAIR_AUTH_TS_HEADER]: String(now),
    [PAIR_AUTH_SIG_HEADER]: b64uEncode(sig),
    [PAIR_AUTH_PK_HEADER]: b64uEncode(pk),
  };
  if (bodyObj !== undefined) headers['content-type'] = 'application/json';
  return new Request(url, { method, headers, body: bodyText || undefined });
}

describe('access key is never read from a URL', () => {
  const secret = 'unit-test-access-key';
  it('accepts the header and ignores rk= in the query', async () => {
    expect(providedAccessSecret(new Request('https://x/v2/g/aa/ws?since=0&rk=' + encodeURIComponent(secret)))).toBe('');
    expect(await accessSecretOk(new Request('https://x/v2/g/aa/ws?since=0&rk=' + encodeURIComponent(secret)), secret)).toBe(false);
    expect(await accessSecretOk(new Request('https://x/v2/health', { headers: { [RELAY_ACCESS_HEADER]: secret } }), secret)).toBe(true);
    expect(await accessSecretOk(new Request('https://x/v2/health?rk=' + encodeURIComponent(secret)), secret)).toBe(false);
  });
});

describe('pairing proof (required when the relay has an access key)', () => {
  it('rejects a stranger and accepts a proof bound to the pairing secret', async () => {
    const st = new MemoryPairStore();
    const kp = await genKp();
    const now = 1_700_000_000_000;
    const opts = { requireProof: true };
    const body = { blob: BLOB };

    expect((await handlePair(new Request(OFFER, { method: 'PUT', body: JSON.stringify(body) }), 'offer', st, now, opts)).status).toBe(401);
    expect((await handlePair(await signed('GET', OFFER, undefined, kp, now), 'offer', st, now, opts)).status).toBe(401);
    expect((await handlePair(await signed('PUT', JOIN, body, kp, now), 'join', st, now, opts)).status).toBe(401);

    const put = await handlePair(await signed('PUT', OFFER, body, kp, now), 'offer', st, now, opts);
    expect(put.status).toBe(200);
    expect(st.getVerifier()).not.toBeNull();

    expect((await handlePair(new Request(OFFER), 'offer', st, now + 1000, opts)).status).toBe(401);
    const got = await handlePair(await signed('GET', OFFER, undefined, kp, now + 1000), 'offer', st, now + 1000, opts);
    expect(got.status).toBe(200);
    expect(await got.json()).toMatchObject({ blob: BLOB });

    const other = await genKp();
    expect((await handlePair(await signed('GET', OFFER, undefined, other, now + 2000), 'offer', st, now + 2000, opts)).status).toBe(401);

    const join = await handlePair(await signed('PUT', JOIN, body, kp, now + 3000), 'join', st, now + 3000, opts);
    expect(join.status).toBe(200);
  });

  it('rejects an expired timestamp, a future timestamp outside the window, and a tampered body', async () => {
    const st = new MemoryPairStore();
    const kp = await genKp();
    const now = 1_700_000_000_000;
    const opts = { requireProof: true };
    const body = { blob: BLOB };
    expect((await handlePair(await signed('PUT', OFFER, body, kp, now), 'offer', st, now, opts)).status).toBe(200);

    expect((await handlePair(await signed('GET', OFFER, undefined, kp, now - REQ_SKEW_MS - 1), 'offer', st, now, opts)).status).toBe(401);
    expect((await handlePair(await signed('GET', OFFER, undefined, kp, now + REQ_SKEW_MS + 1), 'offer', st, now, opts)).status).toBe(401);
    expect((await handlePair(await signed('GET', OFFER, undefined, kp, now - REQ_SKEW_MS + 1000), 'offer', st, now, opts)).status).toBe(200);

    const replayed = await signed('PUT', OFFER, body, kp, now + 5000);
    expect((await handlePair(replayed, 'offer', st, now + 5000, opts)).status).toBe(409);

    const otherBody = { blob: b64uEncode(new Uint8Array(32).fill(9)) };
    const req = await signed('PUT', JOIN, body, kp, now + 6000);
    const tampered = new Request(JOIN, { method: 'PUT', headers: req.headers, body: JSON.stringify(otherBody) });
    expect((await handlePair(tampered, 'join', st, now + 6000, opts)).status).toBe(401);
  });

  it('still allows unauthenticated pairing when proof is not required (older relays)', async () => {
    const st = new MemoryPairStore();
    const body = JSON.stringify({ blob: BLOB });
    expect((await handlePair(new Request(OFFER, { method: 'PUT', body }), 'offer', st, 0)).status).toBe(200);
    expect((await handlePair(new Request(OFFER), 'offer', st, 1000)).status).toBe(200);
  });
});
