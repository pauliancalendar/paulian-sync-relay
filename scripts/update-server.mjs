#!/usr/bin/env node
/**
 * "Update my server": run by .github/workflows/update-server.yml in YOUR copy of this project, when you press
 * Actions → Update my server → Run workflow on GitHub. It:
 *   1. downloads the latest Paulian sync server release (relay-manifest.json + .sig) from the public project;
 *   2. checks the Ed25519 signature against the publisher key pinned below, refuses older versions, and stops quietly
 *      if you already have this version;
 *   3. downloads every file listed in the release and checks each one's SHA-256 (any mismatch: nothing is changed);
 *   4. replaces only the files the template owns (src/, test/, scripts/, docs/, package files, guides), keeps YOUR
 *      Worker name and YOUR [vars] values in wrangler.toml, and keeps the Durable Object migrations append-only;
 *   5. commits as "Paulian Calendar updater" and pushes. Cloudflare then rebuilds and redeploys your server.
 *
 * It never touches your access key (a Cloudflare secret, not in this repository) or your stored data.
 * It never changes .github/workflows/: the workflow's built-in token is not allowed to, so that file is kept tiny and
 * all logic lives here, where an update can improve it (this script is itself part of every verified release).
 *
 *   node scripts/update-server.mjs            # what the workflow runs
 *   node scripts/update-server.mjs --dry-run  # check and show what would change; writes nothing
 */
import { execFileSync } from 'node:child_process';
import { existsSync, mkdirSync, readdirSync, readFileSync, rmSync, statSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  MERGED_FILE, OWNED_DIRS, OWNED_FILES, ReleaseError, UPSTREAM_REPO, WORKFLOW_FILE, MAX_MANIFEST_BYTES, MAX_FILE_BYTES,
  checkFile, checkRelease, isOwnedPath, mergeWrangler, sha256Hex,
} from './lib/release.mjs';

/**
 * The Paulian Calendar publisher's Ed25519 public key (raw 32 bytes, base64). Pinned here on purpose: a release is
 * accepted only if it was signed with the matching private key, which never leaves the publisher's own computer.
 * To change it, a release signed with the OLD key must ship a new copy of this file.
 */
export const PUBLISHER_PUBLIC_KEY = 'tVB/AZ7BDaUYFdYHObJ9nvwO1jOE3pufqX0Z1vEzUlc=';

const RELEASE_BASE = `https://github.com/${UPSTREAM_REPO}/releases/latest/download`;
const rawUrl = (tag, path) => `https://raw.githubusercontent.com/${UPSTREAM_REPO}/${tag}/${path}`;

async function download(url, max) {
  const res = await fetch(url, { redirect: 'follow', headers: { 'User-Agent': 'paulian-sync-relay-updater' } });
  if (!res.ok) throw new ReleaseError(`Could not download ${url} (HTTP ${res.status}).`);
  const buf = Buffer.from(await res.arrayBuffer());
  if (buf.length > max) throw new ReleaseError(`${url} is larger than allowed.`);
  return buf;
}

/** Template-owned files present in the working tree now (to remove the ones a release no longer has). */
export function ownedFilesOnDisk(root) {
  const out = [];
  const walk = (rel) => {
    for (const name of readdirSync(join(root, rel))) {
      if (name === '.DS_Store') continue;
      const p = rel + name;
      if (statSync(join(root, p)).isDirectory()) walk(p + '/'); else if (isOwnedPath(p)) out.push(p);
    }
  };
  for (const d of OWNED_DIRS) if (existsSync(join(root, d))) walk(d);
  for (const f of OWNED_FILES) if (existsSync(join(root, f))) out.push(f);
  return out;
}

/**
 * Applies a verified release to `root`. `files` maps path -> verified bytes. Returns the list of changes.
 * Writes nothing when dryRun is true.
 */
export function applyRelease(root, manifest, files, { dryRun = false } = {}) {
  const changes = [];
  const listed = new Set(manifest.files.map((f) => f.path));
  // wrangler.toml first: if it cannot be merged safely, stop before anything else is touched.
  const oldToml = readFileSync(join(root, MERGED_FILE), 'utf8');
  const merged = mergeWrangler(oldToml, files.get(MERGED_FILE).toString('utf8'));
  const writes = [];
  if (merged !== oldToml) writes.push([MERGED_FILE, Buffer.from(merged)]);
  for (const f of manifest.files) {
    if (f.path === MERGED_FILE || f.path === WORKFLOW_FILE) continue;
    const target = join(root, f.path);
    const now = existsSync(target) ? readFileSync(target) : null;
    if (!now || sha256Hex(now) !== f.sha256) writes.push([f.path, files.get(f.path)]);
  }
  const removes = ownedFilesOnDisk(root).filter((p) => !listed.has(p));
  for (const [p, bytes] of writes) {
    changes.push(`update ${p}`);
    if (!dryRun) { mkdirSync(dirname(join(root, p)), { recursive: true }); writeFileSync(join(root, p), bytes); }
  }
  for (const p of removes) {
    changes.push(`remove ${p}`);
    if (!dryRun) rmSync(join(root, p));
  }
  const wf = manifest.files.find((f) => f.path === WORKFLOW_FILE);
  const wfNow = existsSync(join(root, WORKFLOW_FILE)) ? sha256Hex(readFileSync(join(root, WORKFLOW_FILE))) : null;
  const workflowChanged = !!wf && wf.sha256 !== wfNow;
  return { changes, workflowChanged };
}

function git(args, opts = {}) { return execFileSync('git', args, { encoding: 'utf8', stdio: ['ignore', 'pipe', 'inherit'], ...opts }); }

async function main() {
  const dryRun = process.argv.includes('--dry-run');
  const root = join(dirname(fileURLToPath(import.meta.url)), '..');
  const current = JSON.parse(readFileSync(join(root, 'package.json'), 'utf8')).version;
  console.log(`Your server's code is version ${current}. Looking for the latest release of ${UPSTREAM_REPO}...`);

  const manifestBytes = await download(`${RELEASE_BASE}/relay-manifest.json`, MAX_MANIFEST_BYTES);
  const sigText = (await download(`${RELEASE_BASE}/relay-manifest.json.sig`, 1024)).toString('utf8');
  const { action, manifest } = checkRelease({ manifestBytes, sigText, publicKey: PUBLISHER_PUBLIC_KEY, currentVersion: current });
  if (action === 'current') { console.log(`You already have the latest version (${current}). Nothing to do.`); return; }
  console.log(`Signed release ${manifest.version} verified. Downloading ${manifest.files.length} files...`);

  const files = new Map();
  for (const f of manifest.files) {
    const bytes = await download(rawUrl(manifest.tag, f.path), MAX_FILE_BYTES);
    checkFile(f, bytes);
    files.set(f.path, bytes);
  }
  const { changes, workflowChanged } = applyRelease(root, manifest, files, { dryRun });
  for (const c of changes) console.log(`  ${c}`);
  if (workflowChanged) console.log(`Note: the release has a newer ${WORKFLOW_FILE}. GitHub does not let this workflow change it; the old one keeps working. To update it, see UPDATE.md.`);
  if (dryRun) { console.log('Dry run: nothing was written.'); return; }
  if (!git(['status', '--porcelain']).trim()) { console.log('Nothing changed.'); return; }

  // Commit as the updater. The address is GitHub's no-reply form for the Actions bot.
  const email = ['41898282+github-actions[bot]', 'users.noreply.github.com'].join('@');
  const env = { ...process.env, GIT_AUTHOR_NAME: 'Paulian Calendar updater', GIT_AUTHOR_EMAIL: email, GIT_COMMITTER_NAME: 'Paulian Calendar updater', GIT_COMMITTER_EMAIL: email };
  git(['add', '-A'], { cwd: root }); // a fresh Actions checkout: only the updater's own changes are in the tree
  git(['commit', '-q', '-m', `Update the Paulian sync server to ${manifest.version}`], { cwd: root, env });
  const branch = process.env.GITHUB_REF_NAME;
  if (branch && /^[A-Za-z0-9._/-]{1,100}$/.test(branch)) {
    git(['push', 'origin', `HEAD:refs/heads/${branch}`], { cwd: root });
    console.log(`Done: committed and pushed to ${branch}. Cloudflare now rebuilds your server (about a minute).`);
  } else {
    console.log('Committed locally (not running in GitHub Actions, so nothing was pushed).');
  }
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  main().catch((e) => {
    console.error(e instanceof ReleaseError ? `Update stopped: ${e.message}` : e);
    process.exit(1);
  });
}
