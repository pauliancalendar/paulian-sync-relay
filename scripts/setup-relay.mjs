#!/usr/bin/env node
/**
 * Prepare a new Paulian sync relay: pick a legitimate-looking random Worker name and an access key.
 * Does not deploy anything. Writes only the Worker name into wrangler.toml (unless --print).
 * The access key is printed once — set it with `npx wrangler secret put RELAY_ACCESS_SECRET` or
 * in the dashboard under Settings → Variables and Secrets (type Secret). Never put it in wrangler.toml.
 */
import { readFileSync, writeFileSync } from 'node:fs';
import { randomBytes } from 'node:crypto';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const alphabet = 'abcdefghijklmnopqrstuvwxyz0123456789';
const suffix = [...randomBytes(8)].map((b) => alphabet[b % 36]).join('');
const name = `paulian-calendar-sync-${suffix}`;
const secret = randomBytes(32).toString('hex');
const printOnly = process.argv.includes('--print');
const root = join(dirname(fileURLToPath(import.meta.url)), '..');

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
