import { describe, expect, it } from 'vitest';
import { readFileSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import {
  MemoryGroupStore, RELAY_ACCESS_HEADER, RELAY_VERSION, accessSecretOk, configuredAccessSecret, discardEmptyProbe,
  healthResponse2, verifyCreateGroupRequest, webCrypto2,
} from '../src/core2';
import { LogType } from '../src/proto2';
import { authHeader, b64u, logEntry, newGrp, ready } from './helpers2';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');

describe('empty-store cleanup', () => {
  it('discards a store that never received a write and leaves a used store alone', () => {
    const empty = new MemoryGroupStore();
    expect(discardEmptyProbe(empty)).toBe(true);
    const used = new MemoryGroupStore();
    used.setLastWriteDay(10);
    used.insert([{ device: 'd', epoch: 0, index: 0, kind: 1, day: 10, blob: new Uint8Array(8) }]);
    expect(discardEmptyProbe(used)).toBe(false);
    expect(used.usage().count).toBe(1);
    expect(used.lastWriteDay()).toBe(10);
  });
});

describe('optional access key', () => {
  const secret = 'unit-test-access-key';
  it('is inactive when the binding is missing or blank', () => {
    expect(configuredAccessSecret(undefined)).toBeNull();
    expect(configuredAccessSecret('  ')).toBeNull();
    expect(configuredAccessSecret(secret)).toBe(secret);
  });
  it('allows every request when no key is configured', async () => {
    const req = new Request('https://example.workers.dev/v2/health');
    expect(await accessSecretOk(req, undefined)).toBe(true);
    expect(await accessSecretOk(req, '')).toBe(true);
  });
  it('accepts only the header and never a query parameter', async () => {
    expect(await accessSecretOk(new Request('https://x/v2/health', { headers: { [RELAY_ACCESS_HEADER]: secret } }), secret)).toBe(true);
    expect(await accessSecretOk(new Request('https://x/v2/g/aa/ws?since=0&rk=' + encodeURIComponent(secret)), secret)).toBe(false);
    expect(await accessSecretOk(new Request('https://x/v2/health'), secret)).toBe(false);
    expect(await accessSecretOk(new Request('https://x/v2/health', { headers: { [RELAY_ACCESS_HEADER]: 'nope' } }), secret)).toBe(false);
  });
});

describe('create-request verifier', () => {
  it('accepts only a signed genesis or a signed seed, never a plain read of an unknown group', async () => {
    await ready();
    const { g, founder } = newGrp();
    const entry = logEntry(g, founder, LogType.Genesis, [founder]);
    const path = `/v2/g/${g.gidHex}/log`;
    const body = new TextEncoder().encode(JSON.stringify({ entry: b64u(entry) }));
    const hdr = authHeader(founder, 'POST', path, '', body);
    expect(await verifyCreateGroupRequest(webCrypto2, g.gidHex, 'POST', path, '', body, hdr)).toBe(true);
    expect(await verifyCreateGroupRequest(webCrypto2, g.gidHex, 'GET', `/v2/g/${g.gidHex}/changes`, '?since=0', new Uint8Array(0), hdr)).toBe(false);
    expect(await verifyCreateGroupRequest(webCrypto2, g.gidHex, 'POST', path, '', body, null)).toBe(false);
    const stranger = newGrp().founder;
    const bad = authHeader(stranger, 'POST', path, '', body);
    expect(await verifyCreateGroupRequest(webCrypto2, g.gidHex, 'POST', path, '', body, bad)).toBe(false);
  });
});

describe('health and version', () => {
  it('health still carries only the fields the apps check, at version 1.3.0', async () => {
    expect(RELAY_VERSION).toBe('1.3.0');
    expect(JSON.parse(readFileSync(join(root, 'package.json'), 'utf-8')).version).toBe(RELAY_VERSION);
    expect(await healthResponse2('cloudflare-worker').json()).toMatchObject({
      ok: true, service: 'paulian-sync-relay', relayVersion: '1.3.0', protocol: 2, versions: [2], impl: 'cloudflare-worker',
    });
  });
});

describe('setup script', () => {
  it('prints a legitimate-looking Worker name and a 64-character access key without writing them when asked', () => {
    const r = spawnSync('node', [join(root, 'scripts/setup-relay.mjs'), '--print'], { encoding: 'utf8' });
    expect(r.status).toBe(0);
    const name = /Worker name: (paulian-calendar-sync-[a-z0-9]{8})/.exec(r.stdout);
    const key = /Access key:  ([0-9a-f]{64})/.exec(r.stdout);
    expect(name?.[1]).toMatch(/^paulian-calendar-sync-[a-z0-9]{8}$/);
    expect(key?.[1]).toHaveLength(64);
    const toml = readFileSync(join(root, 'wrangler.toml'), 'utf8');
    expect(toml).toMatch(/^name = "paulian-sync-server"$/m);
    expect(toml).not.toContain(name![1]);
    expect(toml).not.toContain(key![1]);
  });
});
