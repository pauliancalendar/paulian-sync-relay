/**
 * Signed releases and the "Update my server" workflow.
 * The key pair used here is a TEST key generated fresh for each run. It is never written to disk and is not the
 * publisher key; the real public key is pinned in scripts/update-server.mjs by the publisher.
 */
import { describe, expect, it } from 'vitest';
import { cpSync, existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync, mkdirSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { generateKeyPairSync } from 'node:crypto';
import { buildManifest, releaseFiles } from '../scripts/build-release.mjs';
import { rawPublicKeyB64, signBytes } from '../scripts/sign-manifest.mjs';
import { PUBLISHER_PUBLIC_KEY, applyRelease } from '../scripts/update-server.mjs';
import {
  PLACEHOLDER_KEY, ReleaseError, WORKFLOW_FILE, checkFile, checkRelease, mergeWrangler, migrationTags, parseManifest, sha256Hex, workerName,
} from '../scripts/lib/release.mjs';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const TEST_KEY = generateKeyPairSync('ed25519').privateKey; // TEST ONLY
const TEST_PUB = rawPublicKeyB64(TEST_KEY);
const OTHER_PUB = rawPublicKeyB64(generateKeyPairSync('ed25519').privateKey); // TEST ONLY

const manifestText = buildManifest(root);
const manifestBytes = Buffer.from(manifestText);
const manifest = JSON.parse(manifestText);
const sig = signBytes(manifestBytes, TEST_KEY);
const withVersion = (v) => {
  const m = { ...manifest, version: v, tag: `v${v}` };
  const b = Buffer.from(JSON.stringify(m));
  return { b, s: signBytes(b, TEST_KEY) };
};

describe('release manifest', () => {
  it('lists exactly the template-owned tracked files, each with its real hash and size', () => {
    expect(manifest.files.map((f) => f.path)).toEqual(releaseFiles(root));
    for (const f of manifest.files) {
      const bytes = readFileSync(join(root, f.path));
      expect(f.sha256, f.path).toBe(sha256Hex(bytes));
      expect(f.bytes, f.path).toBe(bytes.length);
    }
    const paths = manifest.files.map((f) => f.path);
    for (const need of ['wrangler.toml', 'src/index.ts', 'scripts/update-server.mjs', 'scripts/lib/release.mjs', WORKFLOW_FILE]) expect(paths).toContain(need);
    expect(paths.some((p) => p.startsWith('node_modules') || p.endsWith('.pem') || p.includes('.DS_Store'))).toBe(false);
  });

  it('carries the version, plain notes, security flag and the append-only migration list', () => {
    const pkg = JSON.parse(readFileSync(join(root, 'package.json'), 'utf8'));
    expect(manifest.version).toBe(pkg.version);
    expect(manifest.tag).toBe(`v${pkg.version}`);
    expect(typeof manifest.security).toBe('boolean');
    expect(manifest.notes.length).toBeGreaterThan(0);
    for (const n of manifest.notes) expect(n).not.toMatch(/[<>]/);
    expect(manifest.migrations).toEqual(migrationTags(readFileSync(join(root, 'wrangler.toml'), 'utf8')));
  });

  it('rejects a path outside the template, a duplicate, or markup in the notes', () => {
    const bad = (patch) => () => parseManifest(Buffer.from(JSON.stringify({ ...manifest, ...patch })));
    expect(bad({ files: [...manifest.files, { path: '../evil.sh', sha256: 'a'.repeat(64), bytes: 1 }] })).toThrow(ReleaseError);
    expect(bad({ files: [...manifest.files, { path: '.github/workflows/other.yml', sha256: 'a'.repeat(64), bytes: 1 }] })).toThrow(ReleaseError);
    expect(bad({ files: [...manifest.files, manifest.files[0]] })).toThrow(ReleaseError);
    expect(bad({ notes: ['<b>hi</b>'] })).toThrow(ReleaseError);
    expect(bad({ repo: 'someone/else' })).toThrow(ReleaseError);
  });
});

describe('verifying a release', () => {
  it('accepts a correctly signed newer release, and does nothing for the same version', () => {
    expect(checkRelease({ manifestBytes, sigText: sig, publicKey: TEST_PUB, currentVersion: '1.2.0' }).action).toBe('update');
    expect(checkRelease({ manifestBytes, sigText: sig, publicKey: TEST_PUB, currentVersion: manifest.version }).action).toBe('current');
  });
  it('refuses unsigned, tampered, wrongly signed and downgraded releases', () => {
    const go = (o) => () => checkRelease({ manifestBytes, sigText: sig, publicKey: TEST_PUB, currentVersion: '1.0.0', ...o });
    expect(go({ sigText: '' })).toThrow(/not signed/);
    expect(go({ sigText: undefined })).toThrow(/not signed/);
    expect(go({ sigText: 'not-a-signature' })).toThrow(/signature/);
    expect(go({ manifestBytes: Buffer.from(manifestText.replace('"security": true', '"security": false').replace('"security": false', '"security": true') + ' ') })).toThrow(/signature/);
    expect(go({ manifestBytes: Buffer.from(manifestText.replace(manifest.files[0].sha256, 'f'.repeat(64))) })).toThrow(/signature/);
    expect(go({ publicKey: OTHER_PUB })).toThrow(/signature/);
    const old = withVersion('1.1.0');
    expect(go({ manifestBytes: old.b, sigText: old.s, currentVersion: '1.2.0' })).toThrow(/older/);
  });
  it('refuses to run with the placeholder publisher key', () => {
    expect(() => checkRelease({ manifestBytes, sigText: sig, publicKey: PLACEHOLDER_KEY, currentVersion: '1.0.0' })).toThrow(/publisher key is not set/);
  });
  it('the pinned key is either the placeholder or a real 32-byte key', () => {
    expect(PUBLISHER_PUBLIC_KEY === PLACEHOLDER_KEY || Buffer.from(PUBLISHER_PUBLIC_KEY, 'base64').length === 32).toBe(true);
  });
  it('rejects a downloaded file that does not match its hash', () => {
    const f = manifest.files.find((x) => x.path === 'src/index.ts');
    expect(() => checkFile(f, Buffer.from('export default {}'))).toThrow(/does not match/);
    expect(() => checkFile(f, readFileSync(join(root, 'src/index.ts')))).not.toThrow();
  });
});

describe('wrangler.toml merge', () => {
  const tmpl = readFileSync(join(root, 'wrangler.toml'), 'utf8');
  const mine = tmpl.replace(/^name = "[^"]+"/m, 'name = "paulian-calendar-sync-k7m2nq9p"').replace('RETENTION_DAYS_V2 = "90"', 'RETENTION_DAYS_V2 = "30"');
  it('keeps your Worker name and your [vars] values', () => {
    const out = mergeWrangler(mine, tmpl);
    expect(workerName(out)).toBe('paulian-calendar-sync-k7m2nq9p');
    expect(out).toContain('RETENTION_DAYS_V2 = "30"');
    expect(migrationTags(out)).toEqual(migrationTags(tmpl));
  });
  it('keeps a var you added and takes new template entries', () => {
    const out = mergeWrangler(mine.replace('RETENTION_DAYS_V2 = "30"', 'RETENTION_DAYS_V2 = "30"\nMY_NOTE = "x"'), tmpl + '\n[[migrations]]\ntag = "v9"\nnew_sqlite_classes = ["X"]\n');
    expect(out).toContain('MY_NOTE = "x"');
    expect(migrationTags(out).at(-1)).toBe('v9');
  });
  it('refuses settings it cannot keep, and migrations that are not append-only', () => {
    expect(() => mergeWrangler(mine.replace('workers_dev = true', 'workers_dev = true\nroutes = [{ pattern = "x.example/*" }]'), tmpl)).toThrow(/does not know how to keep/);
    expect(() => mergeWrangler(mine + '\nhead_sampling_rate = 1\n', tmpl)).toThrow(/does not know how to keep/);
    expect(() => mergeWrangler(mine + '\n[[d1_databases]]\nbinding = "DB"\n', tmpl)).toThrow(/does not know how to keep/);
    expect(() => mergeWrangler(mine.replace('tag = "v3"', 'tag = "v3b"'), tmpl)).toThrow(/append-only/);
    expect(() => mergeWrangler(mine.replace(/^name = .*$/m, ''), tmpl)).toThrow(/Worker name/);
  });
});

describe('applying a release to your copy', () => {
  it('replaces template files, removes stale ones, keeps your name and settings, never writes the workflow', () => {
    const dir = mkdtempSync(join(tmpdir(), 'relay-upd-'));
    try {
      for (const f of releaseFiles(root)) { mkdirSync(dirname(join(dir, f)), { recursive: true }); cpSync(join(root, f), join(dir, f)); }
      const tmpl = readFileSync(join(root, 'wrangler.toml'), 'utf8');
      writeFileSync(join(dir, 'wrangler.toml'), tmpl.replace(/^name = "[^"]+"/m, 'name = "paulian-sync-relay"'));
      writeFileSync(join(dir, 'src/index.ts'), '// old code');
      writeFileSync(join(dir, 'src/retired.ts'), '// gone in the new release');
      writeFileSync(join(dir, 'my-notes.md'), 'mine, not the template\'s');
      rmSync(join(dir, WORKFLOW_FILE));
      const files = new Map(manifest.files.map((f) => [f.path, readFileSync(join(root, f.path))]));
      const dry = applyRelease(dir, manifest, files, { dryRun: true });
      expect(readFileSync(join(dir, 'src/index.ts'), 'utf8')).toBe('// old code');
      const { changes, workflowChanged } = applyRelease(dir, manifest, files);
      expect(changes).toEqual(dry.changes);
      expect(changes).toContain('update src/index.ts');
      expect(changes).toContain('remove src/retired.ts');
      expect(readFileSync(join(dir, 'src/index.ts'))).toEqual(readFileSync(join(root, 'src/index.ts')));
      expect(existsSync(join(dir, 'src/retired.ts'))).toBe(false);
      expect(existsSync(join(dir, 'my-notes.md'))).toBe(true);
      expect(workerName(readFileSync(join(dir, 'wrangler.toml'), 'utf8'))).toBe('paulian-sync-relay');
      expect(existsSync(join(dir, WORKFLOW_FILE))).toBe(false);
      expect(workflowChanged).toBe(true);
      expect(applyRelease(dir, manifest, files).changes).toEqual([]); // already current
    } finally { rmSync(dir, { recursive: true, force: true }); }
  });
});

describe('the workflow file', () => {
  const yml = readFileSync(join(root, WORKFLOW_FILE), 'utf8');
  it('runs only when you press Run workflow, with write access to contents and nothing else', () => {
    expect(yml).toMatch(/^on:\n {2}workflow_dispatch:\n/m);
    expect(yml).not.toMatch(/^\s+(push|schedule|pull_request|workflow_run|repository_dispatch):/m);
    expect(yml).toMatch(/^permissions:\n {2}contents: write\nconcurrency:/m);
    expect(yml).toMatch(/uses: actions\/checkout@[0-9a-f]{40} #/);
    expect(yml).toContain('run: node scripts/update-server.mjs');
    expect(yml).not.toMatch(/secrets\./);
  });
});
