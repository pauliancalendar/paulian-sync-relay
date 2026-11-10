#!/usr/bin/env node
/**
 * Publisher tool, run OFFLINE on the publisher's own computer. Never commit or upload the private key file.
 *
 *   node scripts/sign-manifest.mjs --generate-key ~/PaulianSigning/relay-signing.pem
 *       Creates a new Ed25519 key pair (private key file readable only by you) and prints the PUBLIC key to pin in
 *       scripts/update-server.mjs and in the apps. Refuses to overwrite a file or to write inside this repository.
 *   node scripts/sign-manifest.mjs --public-key --key ~/PaulianSigning/relay-signing.pem
 *       Prints the public key of an existing private key file.
 *   node scripts/sign-manifest.mjs --key ~/PaulianSigning/relay-signing.pem dist/relay-manifest.json
 *       Writes dist/relay-manifest.json.sig (base64 Ed25519 signature over the exact file bytes) and checks it.
 */
import { createPrivateKey, createPublicKey, generateKeyPairSync, sign, verify } from 'node:crypto';
import { existsSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname, join, resolve, sep } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = resolve(join(dirname(fileURLToPath(import.meta.url)), '..'));
const insideRepo = (p) => resolve(p) === ROOT || resolve(p).startsWith(ROOT + sep);

/** Raw 32-byte Ed25519 public key in base64 (the form pinned in the updater and the apps). */
export function rawPublicKeyB64(keyObject) {
  const jwk = createPublicKey(keyObject).export({ format: 'jwk' });
  return Buffer.from(jwk.x, 'base64url').toString('base64');
}

export function signBytes(bytes, privateKey) {
  const sig = sign(null, bytes, privateKey).toString('base64');
  if (!verify(null, bytes, createPublicKey(privateKey), Buffer.from(sig, 'base64'))) throw new Error('signature self-check failed');
  return sig;
}

function arg(name) { const i = process.argv.indexOf(name); return i > 0 ? process.argv[i + 1] : undefined; }

function main() {
  const gen = arg('--generate-key');
  if (gen) {
    if (insideRepo(gen)) throw new Error('Keep the private key outside this repository.');
    if (existsSync(gen)) throw new Error(`${gen} already exists; not overwriting it.`);
    const { privateKey } = generateKeyPairSync('ed25519');
    writeFileSync(gen, privateKey.export({ format: 'pem', type: 'pkcs8' }), { mode: 0o600, flag: 'wx' });
    console.log(`Private key written to ${gen} (only you can read it). Back it up offline.`);
    console.log(`Public key (pin this): ${rawPublicKeyB64(privateKey)}`);
    return;
  }
  const keyPath = arg('--key');
  if (!keyPath) throw new Error('Pass --key <path to your private key file>.');
  if (insideRepo(keyPath)) throw new Error('The private key must not be inside this repository.');
  const privateKey = createPrivateKey(readFileSync(keyPath));
  if (privateKey.asymmetricKeyType !== 'ed25519') throw new Error('That is not an Ed25519 key.');
  if (process.argv.includes('--public-key')) { console.log(rawPublicKeyB64(privateKey)); return; }
  const file = process.argv.slice(2).filter((a, i, all) => !a.startsWith('--') && all[i - 1] !== '--key').pop();
  if (!file) throw new Error('Pass the manifest file to sign, e.g. dist/relay-manifest.json');
  const sig = signBytes(readFileSync(file), privateKey);
  writeFileSync(`${file}.sig`, sig + '\n');
  console.log(`Signed: ${file}.sig  (public key ${rawPublicKeyB64(privateKey)})`);
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  try { main(); } catch (e) { console.error(String(e.message ?? e)); process.exit(1); }
}
