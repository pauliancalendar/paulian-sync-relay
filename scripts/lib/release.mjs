/**
 * Shared, dependency-free helpers for signed relay releases. Used by:
 *   - scripts/build-release.mjs   (publisher: builds relay-manifest.json from this repository)
 *   - scripts/sign-manifest.mjs   (publisher: signs it offline with an Ed25519 private key file)
 *   - scripts/update-server.mjs   (your copy, in GitHub Actions: verifies a release and updates your files)
 *
 * Trust model: a release is the file relay-manifest.json plus relay-manifest.json.sig (base64 Ed25519 signature over
 * the exact bytes of the manifest). The manifest lists every template file with its SHA-256. The updater accepts a
 * release only if the signature verifies against the publisher key pinned in scripts/update-server.mjs, the version is
 * newer than yours, and every downloaded file matches its hash. Where the bytes came from does not matter after that.
 */
import { createHash, createPublicKey, verify as edVerify } from 'node:crypto';

export const MANIFEST_KIND = 'paulian-sync-relay';
export const MANIFEST_SCHEMA = 1;
export const UPSTREAM_REPO = 'pauliancalendar/paulian-sync-relay';
export const MAX_MANIFEST_BYTES = 64 * 1024;
export const MAX_FILE_BYTES = 2 * 1024 * 1024;
export const MAX_TOTAL_BYTES = 12 * 1024 * 1024;
export const MAX_NOTES = 8;
export const MAX_NOTE_CHARS = 200;
/** A public key that was never filled in. The updater refuses to run until the real key is pinned. */
export const PLACEHOLDER_KEY = 'PASTE_THE_PUBLISHER_PUBLIC_KEY_HERE';

/** Folders the template owns completely: files here that are not in a release are removed by an update. */
export const OWNED_DIRS = ['src/', 'test/', 'scripts/', 'docs/'];
/** Single files the template owns (replaced as a whole). */
export const OWNED_FILES = [
  '.dev.vars.example', '.gitignore', 'DEPLOY.md', 'LICENSE', 'NOTICE', 'README.md', 'UPDATE.md',
  'package.json', 'package-lock.json', 'release-notes.json', 'tsconfig.json',
];
/** Merged, never replaced: your Worker name and your [vars] values are kept. */
export const MERGED_FILE = 'wrangler.toml';
/** Listed with its hash so you can tell if it changed, but never written: GITHUB_TOKEN cannot change workflow files. */
export const WORKFLOW_FILE = '.github/workflows/update-server.yml';

export class ReleaseError extends Error {}
const fail = (msg) => { throw new ReleaseError(msg); };

const VERSION_RE = /^(0|[1-9]\d{0,5})\.(0|[1-9]\d{0,5})\.(0|[1-9]\d{0,5})$/;
export function parseVersion(v) {
  const m = typeof v === 'string' ? VERSION_RE.exec(v) : null;
  return m ? [Number(m[1]), Number(m[2]), Number(m[3])] : null;
}
export function compareVersions(a, b) {
  const x = parseVersion(a), y = parseVersion(b);
  if (!x || !y) return null;
  for (let i = 0; i < 3; i++) if (x[i] !== y[i]) return x[i] - y[i];
  return 0;
}

export const sha256Hex = (bytes) => createHash('sha256').update(bytes).digest('hex');

const PATH_SEG = /^[A-Za-z0-9_][A-Za-z0-9._-]*$|^\.(dev\.vars\.example|gitignore|github)$/;
/** A relative path the template may own: plain segments, no "..", no absolute paths, inside the owned set. */
export function isOwnedPath(p) {
  if (typeof p !== 'string' || p.length === 0 || p.length > 200) return false;
  const segs = p.split('/');
  if (!segs.every((s) => PATH_SEG.test(s) && s !== '.' && s !== '..')) return false;
  if (p === MERGED_FILE || p === WORKFLOW_FILE || OWNED_FILES.includes(p)) return true;
  return OWNED_DIRS.some((d) => p.startsWith(d)) && segs.length >= 2;
}

/** Ed25519 public key from its raw 32 bytes in base64. */
export function publicKeyFromBase64(b64) {
  if (typeof b64 !== 'string' || b64 === PLACEHOLDER_KEY) fail('The publisher key is not set in scripts/update-server.mjs.');
  const raw = Buffer.from(b64.trim(), 'base64');
  if (raw.length !== 32) fail('The publisher key must be 32 bytes in base64.');
  return createPublicKey({ key: { kty: 'OKP', crv: 'Ed25519', x: raw.toString('base64url') }, format: 'jwk' });
}

/** True only for a valid base64 Ed25519 signature of exactly these bytes. Missing or malformed signatures are false. */
export function verifySignature(manifestBytes, sigText, publicKeyB64) {
  const key = publicKeyFromBase64(publicKeyB64);
  if (typeof sigText !== 'string') return false;
  const t = sigText.trim();
  if (!/^[A-Za-z0-9+/]{86}==$/.test(t)) return false;
  try { return edVerify(null, manifestBytes, key, Buffer.from(t, 'base64')); } catch { return false; }
}

const DATE_RE = /^\d{4}-\d{2}-\d{2}$/;
// eslint-disable-next-line no-control-regex
const CONTROL = /[\u0000-\u001f\u007f]/;

/** Plain-language notes: 1..8 short lines of plain text (no control characters, no markup). */
export function checkNotes(notes) {
  if (!Array.isArray(notes) || notes.length < 1 || notes.length > MAX_NOTES) fail(`notes must be 1 to ${MAX_NOTES} lines`);
  for (const n of notes) {
    if (typeof n !== 'string' || !n.trim() || n.length > MAX_NOTE_CHARS || CONTROL.test(n) || /[<>]/.test(n)) {
      fail(`each note must be plain text of at most ${MAX_NOTE_CHARS} characters`);
    }
  }
}

/** Parses and checks the manifest shape. Throws ReleaseError on anything unexpected. */
export function parseManifest(bytes) {
  if (!bytes || bytes.length > MAX_MANIFEST_BYTES) fail('The release manifest is missing or too large.');
  let m;
  try { m = JSON.parse(Buffer.from(bytes).toString('utf8')); } catch { fail('The release manifest is not valid JSON.'); }
  if (!m || typeof m !== 'object' || Array.isArray(m)) fail('The release manifest has the wrong shape.');
  if (m.schema !== MANIFEST_SCHEMA || m.kind !== MANIFEST_KIND) fail('This is not a Paulian sync server release.');
  if (m.repo !== UPSTREAM_REPO) fail('The release comes from an unexpected repository.');
  if (!parseVersion(m.version)) fail('The release version is not a plain x.y.z number.');
  if (m.tag !== `v${m.version}`) fail('The release tag does not match its version.');
  if (typeof m.released !== 'string' || !DATE_RE.test(m.released)) fail('The release date is missing.');
  if (m.minApp !== undefined && !parseVersion(m.minApp)) fail('minApp must be a plain x.y.z number.');
  if (typeof m.security !== 'boolean') fail('The security flag is missing.');
  checkNotes(m.notes);
  if (!Array.isArray(m.migrations) || !m.migrations.every((t) => typeof t === 'string' && /^[A-Za-z0-9_-]{1,32}$/.test(t))) fail('The migration list is malformed.');
  if (!Array.isArray(m.files) || m.files.length === 0 || m.files.length > 500) fail('The file list is malformed.');
  const seen = new Set();
  let total = 0;
  for (const f of m.files) {
    if (!f || typeof f !== 'object' || !isOwnedPath(f.path) || seen.has(f.path)) fail(`Bad or duplicate file path in the release: ${String(f?.path)}`);
    if (typeof f.sha256 !== 'string' || !/^[0-9a-f]{64}$/.test(f.sha256)) fail(`Bad hash for ${f.path}`);
    if (!Number.isInteger(f.bytes) || f.bytes < 0 || f.bytes > MAX_FILE_BYTES) fail(`Bad size for ${f.path}`);
    seen.add(f.path); total += f.bytes;
  }
  if (total > MAX_TOTAL_BYTES) fail('The release is too large.');
  for (const need of [MERGED_FILE, 'package.json', 'src/index.ts']) if (!seen.has(need)) fail(`The release does not include ${need}.`);
  return m;
}

/**
 * Everything the updater checks before it touches a file: signature first, then shape, then version.
 * Returns { action: 'update' | 'current', manifest }. Throws ReleaseError (tampered, unsigned, wrong key, downgrade, ...).
 */
export function checkRelease({ manifestBytes, sigText, publicKey, currentVersion }) {
  if (sigText === undefined || sigText === null || String(sigText).trim() === '') fail('The release is not signed. Nothing was changed.');
  if (!verifySignature(manifestBytes, String(sigText), publicKey)) fail('The release signature does not match the Paulian Calendar publisher key. Nothing was changed.');
  const manifest = parseManifest(manifestBytes);
  const cmp = compareVersions(manifest.version, currentVersion);
  if (cmp === null) fail(`Your copy reports an unreadable version (${currentVersion}). Update by hand once (UPDATE.md).`);
  if (cmp < 0) fail(`The release (${manifest.version}) is older than your server (${currentVersion}). Going back is not allowed.`);
  return { action: cmp === 0 ? 'current' : 'update', manifest };
}

/** Checks one downloaded file against the manifest. */
export function checkFile(entry, bytes) {
  if (!bytes || bytes.length !== entry.bytes || sha256Hex(bytes) !== entry.sha256) fail(`${entry.path} does not match the signed release. Nothing was changed.`);
}

// ---------------------------------------------------------------------------------------------------------------
// wrangler.toml: line-based (this repository's file is plain and flat; no TOML library is needed or trusted)

/** Every key (as section.key; top level as key) and every section header. [vars] keys are merged separately. */
export function tomlShape(text) {
  const keys = new Set(), sections = new Set();
  let section = '';
  for (const raw of text.split(/\r?\n/)) {
    const line = raw.replace(/#.*$/, '').trim();
    if (!line) continue;
    const h = /^\[\[?([^\]]+)\]\]?$/.exec(line);
    if (h) { section = h[1].trim(); sections.add(section); continue; }
    const k = /^([A-Za-z0-9_.-]+)\s*=/.exec(line);
    if (k && !(section === 'vars')) keys.add(section ? `${section}.${k[1]}` : k[1]); // [vars] are merged, not compared
  }
  return { keys, sections };
}

export function workerName(text) {
  const m = /^name\s*=\s*"([^"]*)"\s*(#.*)?$/m.exec(text);
  return m ? m[1] : null;
}

/** [vars] entries as written (key -> the full right-hand side, comments dropped). */
export function readVars(text) {
  const vars = new Map();
  let inVars = false;
  for (const raw of text.split(/\r?\n/)) {
    const line = raw.trim();
    if (/^\[/.test(line)) { inVars = line === '[vars]'; continue; }
    if (!inVars || !line || line.startsWith('#')) continue;
    const m = /^([A-Za-z_][A-Za-z0-9_]*)\s*=\s*("(?:[^"\\]|\\.)*"|[0-9]+|true|false)\s*(#.*)?$/.exec(line);
    if (!m) fail(`wrangler.toml: a [vars] line this updater cannot read safely: ${line}`);
    vars.set(m[1], m[2]);
  }
  return vars;
}

/** Migration tags, in order. */
export function migrationTags(text) {
  const tags = [];
  let inMig = false;
  for (const raw of text.split(/\r?\n/)) {
    const line = raw.replace(/#.*$/, '').trim();
    if (/^\[/.test(line)) { inMig = line === '[[migrations]]'; continue; }
    const m = inMig && /^tag\s*=\s*"([^"]+)"$/.exec(line);
    if (m) tags.push(m[1]);
  }
  return tags;
}

/**
 * The new template's wrangler.toml with YOUR Worker name and YOUR [vars] values kept.
 * Refuses (throws) when keeping your file safe is not possible automatically:
 *   - your file has a setting or section the new template does not have (a route, a custom domain, an account id...);
 *   - your migrations are not the start of the new list (the list is append-only; Cloudflare runs only new entries).
 */
export function mergeWrangler(oldText, newText) {
  const name = workerName(oldText);
  if (!name || !/^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$/.test(name)) fail('wrangler.toml: could not read your Worker name (the name = "..." line). Update by hand (UPDATE.md).');
  if (!workerName(newText)) fail('The new wrangler.toml has no name line.');
  const a = tomlShape(oldText), b = tomlShape(newText);
  const extraKeys = [...a.keys].filter((k) => !b.keys.has(k));
  const extraSections = [...a.sections].filter((s) => !b.sections.has(s));
  if (extraKeys.length || extraSections.length) {
    fail(`wrangler.toml: your file has settings this updater does not know how to keep (${[...extraKeys, ...extraSections.map((s) => `[${s}]`)].join(', ')}). Update by hand (UPDATE.md).`);
  }
  const oldTags = migrationTags(oldText), newTags = migrationTags(newText);
  if (oldTags.length > newTags.length || oldTags.some((t, i) => newTags[i] !== t)) {
    fail('wrangler.toml: your Durable Object migrations differ from the template. Migrations are append-only; update by hand (UPDATE.md).');
  }
  const oldVars = readVars(oldText), newVars = readVars(newText);
  const out = [];
  let inVars = false, sawVars = false;
  const keptNames = new Set();
  for (const raw of newText.split(/\r?\n/)) {
    const t = raw.trim();
    if (/^\[/.test(t)) {
      if (inVars) for (const [k, v] of oldVars) if (!newVars.has(k)) out.push(`${k} = ${v}`);
      inVars = t === '[vars]';
      if (inVars) sawVars = true;
      out.push(raw); continue;
    }
    if (/^name\s*=/.test(t) && !keptNames.size) { out.push(`name = "${name}"`); keptNames.add('name'); continue; }
    const m = inVars && /^([A-Za-z_][A-Za-z0-9_]*)\s*=/.exec(t);
    if (m && oldVars.has(m[1])) { out.push(`${m[1]} = ${oldVars.get(m[1])}`); continue; }
    out.push(raw);
  }
  if (inVars) for (const [k, v] of oldVars) if (!newVars.has(k)) out.push(`${k} = ${v}`);
  if (!sawVars && oldVars.size) { out.push('', '[vars]'); for (const [k, v] of oldVars) out.push(`${k} = ${v}`); }
  return out.join('\n');
}
