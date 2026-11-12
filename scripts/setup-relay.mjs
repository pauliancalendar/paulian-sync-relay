#!/usr/bin/env node
/**
 * Prepare a new Paulian sync relay: pick a legitimate-looking random Worker name and an access key.
 * Does not deploy anything. Writes only the Worker name into wrangler.toml (unless --print).
 * `--enable-workers-dev` only turns the Production workers.dev address on and the Preview
 * address off. It does not change the project name and does not print a key.
 * The access key is printed once — set it with `npx wrangler secret put RELAY_ACCESS_SECRET` or
 * in the dashboard under Settings → Variables and Secrets (type Secret). Never put it in wrangler.toml.
 */
import { readFileSync, writeFileSync } from 'node:fs';
import { randomBytes } from 'node:crypto';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const printOnly = process.argv.includes('--print');
const enableOnly = process.argv.includes('--enable-workers-dev');
const root = join(dirname(fileURLToPath(import.meta.url)), '..');

/** Production workers.dev on, Preview off. The project name on the name line is left as it is. */
export function ensureWorkersDev(toml) {
  const newline = toml.includes('\r\n') ? '\r\n' : '\n';
  let next = toml.replace(/\r\n/g, '\n');
  if (/^workers_dev\s*=/m.test(next)) next = next.replace(/^workers_dev\s*=.*$/m, 'workers_dev = true');
  else next = next.replace(/^(name\s*=.*)$/m, '$1\nworkers_dev = true');
  if (/^preview_urls\s*=/m.test(next)) next = next.replace(/^preview_urls\s*=.*$/m, 'preview_urls = false');
  else next = next.replace(/^(workers_dev\s*=.*)$/m, '$1\npreview_urls = false');
  if (newline !== '\n') next = next.replace(/\n/g, newline);
  return next;
}

const invokedDirectly = process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1];
if (invokedDirectly && enableOnly) {
  const file = join(root, 'wrangler.toml');
  const toml = readFileSync(file, 'utf8');
  const next = ensureWorkersDev(toml);
  if (next !== toml) writeFileSync(file, next);
  process.exit(0);
}

if (invokedDirectly && !enableOnly) {
  const alphabet = 'abcdefghijklmnopqrstuvwxyz0123456789';
  const suffix = [...randomBytes(8)].map((b) => alphabet[b % 36]).join('');
  const name = `paulian-calendar-sync-${suffix}`;
  const secret = randomBytes(32).toString('hex');
  if (!printOnly) {
    const file = join(root, 'wrangler.toml');
    const toml = readFileSync(file, 'utf8');
    const next = toml.replace(/^name = "[^"]+"/m, `name = "${name}"`);
    if (next === toml) {
      console.error('Could not find a name = "..." line in wrangler.toml');
      process.exit(1);
    }
    writeFileSync(file, next);
  }
  const addr = `https://${name}.<your-subdomain>.workers.dev`;
  console.log(`Worker name: ${name}`);
  console.log(`Access key:  ${secret}`);
  console.log(`Address:     ${addr}`);
  console.log('');
  console.log('This script does not deploy anything.');
  if (!printOnly) console.log('The Worker name has been written to wrangler.toml. Keep that file if you update later, so the name does not change.');
  console.log('Set the access key after the first deploy (do not put it in wrangler.toml):');
  console.log('  npx wrangler secret put RELAY_ACCESS_SECRET');
  console.log('When asked, paste the access key printed above.');
  console.log('Then paste the same address and access key into Paulian Calendar (Sync → Set up your sync server).');
}
