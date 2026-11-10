#!/usr/bin/env node
/**
 * Publisher tool: builds dist/relay-manifest.json for the version in package.json.
 * The manifest lists every template-owned file (git-tracked, see scripts/lib/release.mjs) with its SHA-256 and size,
 * plus the plain-language notes from release-notes.json. Sign it next with scripts/sign-manifest.mjs (offline).
 * It reads only this repository and writes only dist/. It uploads nothing.
 *
 *   node scripts/build-release.mjs            # writes dist/relay-manifest.json
 *   node scripts/build-release.mjs --check    # builds in memory and checks it; writes nothing
 */
import { execFileSync } from 'node:child_process';
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { MANIFEST_KIND, MANIFEST_SCHEMA, MERGED_FILE, UPSTREAM_REPO, checkNotes, isOwnedPath, migrationTags, parseManifest, parseVersion, sha256Hex } from './lib/release.mjs';

export const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');

/** The template files a release ships: git-tracked, inside the owned set. */
export function releaseFiles(root = ROOT) {
  const tracked = execFileSync('git', ['ls-files', '-z'], { cwd: root, encoding: 'utf8' }).split('\0').filter(Boolean);
  return tracked.filter((p) => isOwnedPath(p)).sort();
}

export function buildManifest(root = ROOT) {
  const pkg = JSON.parse(readFileSync(join(root, 'package.json'), 'utf8'));
  const notes = JSON.parse(readFileSync(join(root, 'release-notes.json'), 'utf8'));
  if (!parseVersion(pkg.version)) throw new Error('package.json version must be x.y.z');
  if (notes.version !== pkg.version) throw new Error(`release-notes.json is for ${notes.version}, package.json says ${pkg.version}`);
  const core = readFileSync(join(root, 'src/core2.ts'), 'utf8');
  if (!core.includes(`RELAY_VERSION = '${pkg.version}'`)) throw new Error(`src/core2.ts RELAY_VERSION must be ${pkg.version}`);
  checkNotes(notes.notes);
  const manifest = {
    schema: MANIFEST_SCHEMA,
    kind: MANIFEST_KIND,
    repo: UPSTREAM_REPO,
    version: pkg.version,
    tag: `v${pkg.version}`,
    released: notes.released,
    ...(notes.minApp ? { minApp: notes.minApp } : {}),
    security: notes.security === true,
    notes: notes.notes,
    migrations: migrationTags(readFileSync(join(root, MERGED_FILE), 'utf8')),
    files: releaseFiles(root).map((path) => {
      const bytes = readFileSync(join(root, path));
      return { path, sha256: sha256Hex(bytes), bytes: bytes.length };
    }),
  };
  const text = JSON.stringify(manifest, null, 2) + '\n';
  parseManifest(Buffer.from(text)); // the same checks the updater applies
  return text;
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  const text = buildManifest();
  if (process.argv.includes('--check')) { console.log('Manifest OK.'); process.exit(0); }
  mkdirSync(join(ROOT, 'dist'), { recursive: true });
  writeFileSync(join(ROOT, 'dist/relay-manifest.json'), text);
  const m = JSON.parse(text);
  console.log(`dist/relay-manifest.json: version ${m.version}, ${m.files.length} files. Commit and tag ${m.tag} first, then sign it offline.`);
}
