# Paulian Sync protocol v2

Status: implemented in this relay and in the Paulian Calendar desktop (Mac, Windows) and Android apps. Test vectors for the wire format (`sync_v2_vectors.json`) are kept with the apps.
Companion: `SECURITY.md` (threat model, what each part fixes, residual risks). v1 is described in `PROTOCOL.md`.

Conventions: `||` is concatenation; integers are big-endian; `hex` is lowercase; `b64u` is base64url without padding;
all strings are UTF-8. `trunc16(x)` is the first 16 bytes. Every value in this document that says "random" comes from the
operating system CSPRNG (libsodium `randombytes_buf`). Test vectors: `tests/sync/core2/vectors/sync_v2_vectors.json`.

## 1. Primitives

| Use | Primitive |
|---|---|
| Signatures | Ed25519 (libsodium `crypto_sign_detached`, RFC 8032, deterministic) |
| Key delivery | NaCl `crypto_box_easy` (X25519 + XSalsa20-Poly1305), explicit 24-byte nonce |
| Data encryption | XChaCha20-Poly1305-IETF, 24-byte nonce, 16-byte tag (`ct = ciphertext || tag`) |
| KDF | HKDF-SHA256 (RFC 5869) with an **empty salt** (= 32 zero bytes) unless stated; `info` is the UTF-8 string given |
| Ratchet / MAC | HMAC-SHA256 |
| Hash | SHA-256 |

SHA-256, HMAC and HKDF come from `@noble/hashes` (pure, audited); everything else from libsodium. On Android use
libsodium-jni / Lazysodium for Ed25519, `crypto_box_easy` and XChaCha20-Poly1305, and `javax.crypto` HmacSHA256 / `MessageDigest`.

## 2. Identities and identifiers

* Each device creates a **fresh key pair per group**: Ed25519 (`edSeed` 32 random bytes -> `edSk`/`edPk`) and an X25519 secret `xSk`
  (32 random bytes) with `xPk = crypto_scalarmult_base(xSk)`. Nothing is shared between groups, so two groups cannot be correlated
  by a device key.
* `groupRoot` is 32 random bytes, created with the group and handed to every new member inside its key package (section 5).
  It never leaves the members.
* **Relay group id** `gid = HKDF(groupRoot, info "paulian-sync/v2/relay-gid", 32)`, shown as 64 hex. The relay learns only this.
  (The id is a name, not a capability: every request is signed, section 4.)
* **Device id** `deviceId = trunc16(SHA-256("paulian-sync/v2/device-id" || gid || edPk))`, shown as 32 hex.

## 3. Wire sizes and padding

Every envelope blob has a total length that is a power of two, 4096 <= len <= 1 MiB (1 048 576). The envelope overhead is
150 bytes (46 header + 24 nonce + 16 tag + 64 signature). The inner plaintext is
`type u8 | len u32 | payload | zero padding` and its length is `bucket - 150`; `bucket` is the smallest power of two
>= 4096 that fits `150 + 5 + payload`. Padding bytes MUST all be zero; a receiver rejects anything else
(canonical padding, no covert channel). Inner types: 0 = Yjs update, 1 = snapshot, 2 = cover (random filler; receivers decrypt and discard it, it carries no state). A snapshot is envelope kind 1 with inner type 1.
The relay therefore sees one of 9 sizes (4 KiB ... 1 MiB), not the change size. Payloads that do not fit 1 MiB are refused by
the sender (split the Yjs update).

## 4. Authenticated relay access (fixes: anyone with the gid could read)

Every HTTP request, and the first WebSocket frame, carries a signature by a device that is a **current member** per the
membership log held by the relay.

```
Authorization: PCS2 d=<deviceId hex>,t=<unix ms>,n=<nonce b64u>,s=<signature b64u>
signed string = "PCS2-REQ" LF METHOD LF path LF canonicalQuery LF sha256hex(body) LF t LF n LF deviceId     (LF = 0x0A, no trailing LF)
signature     = Ed25519(edSk, UTF-8 of the string)
```

* `path` is the URL path (`/v2/g/<gid>/changes`); `canonicalQuery` is the query string without `?` with its `&`-separated parts
  sorted bytewise (`limit=200&since=5`); `body` is the exact request body bytes (empty for GET/DELETE).
* The relay accepts a timestamp within +/- 5 minutes of its clock and rejects a repeated nonce for 15 minutes. Nonce: 16 random bytes.
* Unknown group, unknown device, **a non-member (including a removed device)** and a bad signature all give the same generic
  `401 unauthorized` (the relay never confirms that a group exists). A stale timestamp gives `401 stale_timestamp` and a repeated
  nonce `401 replayed_request` (these two reveal nothing about membership). A removed device therefore just sees 401s and
  concludes `access_lost` after 3 in a row; an already-open WebSocket of a removed device is closed with 4403.
* WebSocket `/v2/g/<gid>/ws?since=N`: first frame `{"type":"auth","d":..,"t":..,"n":..,"s":..}` within 10 s, signed with method `WS`,
  path `/v2/g/<gid>/ws`, query `?since=N` (canonicalised) and an empty body. The server then replays everything after `since` as
  `{"type":"changes","changes":[{"seq","blob"}]}` frames, sends `{"type":"ready","latest","epoch","head","logLength"}`, and pushes
  further `changes` frames live (a client that sees `logLength` grow pulls the log over HTTP). `ping` is answered with `pong`.
  Close codes: 4401 auth (bad frame, bad signature, 10 s timeout), 4403 removed, 4429 rate limited, 4000 group deleted.
* Public: `GET /v2/health` (also `/v1/health` and `/`) -> `{ok, service:"paulian-sync-relay", relayVersion:"1.1.0", protocol:2, versions:[2] (or [1,2] while v1 is on), v1:"readwrite|readonly|off", impl}`. `relayVersion` is the relay software version (semver); a relay without the field is 1.0.0. Nothing else is public.

### Endpoints

| Method + path | Request | Response |
|---|---|---|
| `GET /v2/g/{gid}/log?from=N` | | `{entries:[b64u...] (<= 64 per page), length, head}` |
| `POST /v2/g/{gid}/log` | `{entry: b64u}` appends one membership entry (genesis creates the group; the genesis signer authenticates with the key inside the entry, which binds it to the gid). A stale index/prev -> `409 {error:"log_conflict", length, head}`; a rule violation -> `400 <error code of section 5>`; signer != caller -> `403 signer_mismatch` | `{index, length, head}` |
| `POST /v2/g/{gid}/log` | `{entries:[b64u,...]}` 1..64, **seed mode**: every entry is verified; accepted only if the relay holds a prefix of that chain (or nothing). Used by any member to bring a relay that was down or is new up to date | same |
| `GET /v2/g/{gid}/changes?since=N&limit=200` (limit <= 500) | | `{changes:[{seq,blob}], cursor, latest, more, epoch, logLength, head}` |
| `POST /v2/g/{gid}/changes` | `{changes:[b64u...]}` <= 100 envelopes. Each: size <= 1 MiB, `device == caller`, `epoch == current epoch` (else `409 {error:"stale_epoch", epoch, logLength}`), valid signature (`403 bad_signature`) | `{results:[{seq, duplicate?}], cursor, count}` |
| `POST /v2/g/{gid}/compact` | `{upto: seq}`; allowed only when a snapshot envelope newer than `upto` is stored (else `409 no_snapshot`) | `{deleted: n}` |
| `DELETE /v2/g/{gid}` | | `{deleted:true}`; all data and the log are removed, sockets closed with 4000 |
| `PUT /v2/pair/{pid}/{offer|join|welcome}` | `{blob: b64u}` (16..2048 bytes), unauthenticated, write-once (`409 slot_taken`), 10 min TTL | `{ok:true}` |
| `GET /v2/pair/{pid}/{slot}` | | `{blob}` or `404 empty` |

Other errors: 400 `bad_json`/`bad_entry`/`bad_blob`, 413 (`body_too_large`, `too_many_changes`, `change_too_large`), 429 `rate_limited` (+`retry-after`), 507 `group_quota_exceeded` (64 MiB / 50 000 changes per group).
The relay validates envelope **structure only** (magic, version, epoch within the log, device id is a member, power-of-two size,
signature valid under the member's key, index/prev format). It cannot read content.

## 5. Membership log, epochs and key packages (fixes: no rotation / revocation)

The group state is an append-only, signed, hash-chained **membership log**. `epoch == entry index`. Each entry:

```
"PCM2" | ver=2 | type u8 | prev32 | index u32 | day u32 | signer16 | memberCount u8 |
  members[ id16 | ed32 | x32 ]  (sorted by id, <= 16) |
  pkgCount u8 | pkgs[ to16 | nonce24 | len u16 (=80) | ct80 ] | sig64
type: 0 genesis, 1 add, 2 remove, 3 rotate
day:  unix seconds floored to a multiple of 86400 (no finer timestamps anywhere)
sig:  Ed25519(signerEdSk, "paulian-sync/v2/log" || gid || body)   body = every byte before sig64
entryHash = SHA-256(raw entry including sig)   prev = hash of the previous entry (32 zero bytes for genesis)
```

Rules (error codes in the order they are checked): `bad_entry` (parse), `bad_index` (== current length), `bad_prev`,
`bad_day` (not a multiple of 86400, or earlier than the previous entry's day), member list sane (`bad_member`, `members_not_sorted`,
`bad_device_id` = id does not match `trunc16(SHA-256(domain||gid||ed))`), genesis (`bad_genesis`: index 0, zero prev, exactly one
member = signer; `bad_packages`: none), `no_genesis`, `signer_not_member` (signer must be in the **previous** state),
`member_key_changed` (an id keeps its keys), then by type: add = previous members plus 1..n new (`bad_add`), remove = strict
subset, at least 1 member left unless the signer removes themself and nobody else (`bad_remove`), rotate = same members
(`bad_rotate`); `bad_packages` (exactly one package for every new-state member except the signer, `len == 80`), and last
`bad_signature`.
A signer that is absent from the new member list is allowed: that is **self-removal** (a leaving device announces it; others
should rotate, which any remaining member can do).

**Key package.** For each recipient: `ct = crypto_box_easy(epochKey32 || groupRoot32, nonce24, recipientXPk, signerXSk)` (80 bytes).
The recipient opens it with `signerXPk` (taken from the previous state for a self-removal, otherwise from the new state) and its own
`xSk`. `epochKey` is 32 fresh random bytes **per entry**: it is not derived from the previous epoch's key, so a removed or
compromised device that held epoch n learns nothing about epoch n+1 (post-compromise security) and a new member cannot read
epochs before it was added (the entry does not contain the old keys).

After every membership change the device that made it publishes a full **snapshot** (kind 2) in the new epoch, which is how a new member receives the current data (it cannot decrypt anything from earlier epochs).

Who may append: any current member (see residual risks: members are equals; a member can remove others). Add requires the
approved pairing flow (section 8). The relay checks signature and all rules above (it holds public keys only) and answers 409 on a
conflict, so concurrent changes are serialised. Clients also check the rules themselves and keep their own copy of the log;
if two relays return different entries for the same index the client reports a fork.

## 6. Message keys: per-sender hash ratchet (fixes: no forward secrecy)

Every (epoch, sender device) has its own chain, derived only from the epoch key and the sender's device id:

```
ck_0       = HKDF(epochKey, salt = "", info = "paulian-sync/v2/chain" || deviceId16, 32)
msgKey_n   = HMAC-SHA256(ck_n, 0x01)
ck_(n+1)   = HMAC-SHA256(ck_n, 0x02)
```

A sender uses index n = 0,1,2,... exactly once; it keeps only `ck_n` and wipes `ck_(n-1)` and the message key right after use.
A receiver advances the chain to the index in the header; keys for skipped indices (at most `MAX_SKIP` = 2000) are kept until
the late message arrives (then used once and wiped) and a gap warning appears after 10 minutes. Because keys are one-way,
a device that is compromised at time t can decrypt nothing that it had already consumed and, after the next rotation, nothing new.
Old-epoch chains are discarded when the epoch changes (after their pending skipped keys are used or given up).
Rotation: a client appends a `rotate` entry on explicit "Rotate keys", after removing a device (the `remove` entry itself already
carries a fresh epoch key), when another member left without deleting, and automatically when the last rotation is older than
30 days (checked every 30 s while the group has more than one member; it waits until nothing is pending). There is no
message-count trigger. Android SHOULD implement the same 30-day rule.

## 7. Envelope `PCS2`

```
header (46) = "PCS2" | ver=2 | kind u8 (1 update, 2 snapshot) | epoch u32 | device16 | index u32 | prev16
envelope    = header | nonce24 | AEAD(msgKey_index, nonce, innerPadded, aad) | sig64
aad         = "paulian-sync/v2/aad" || gid || header || entryHash(of the membership entry that started this epoch)
sig         = Ed25519(edSk, "paulian-sync/v2/env" || gid || everything before sig64)
prev        = trunc16(SHA-256(previous envelope blob of the same device and epoch)); 16 zero bytes for index 0
```

Receiver order: parse; check size is a power of two; look up the sender in the epoch's member set; **verify the signature first**
(so an attacker cannot make us burn ratchet keys); check the index is not already consumed; derive the key (consume it);
AEAD-open with the aad; check padding is canonical; record `trunc16(SHA-256(blob))` for index n and compare the `prev` of index n+1
with the recorded hash of index n -> a mismatch is a **fork** (relay or attacker showed different histories to different devices,
or a restored backup kept writing). A missing index below the highest seen is a **gap** (relay dropped/delayed a change).
Both are surfaced to the user as warnings; neither is silently ignored.

Binding the epoch's start hash into the AAD makes a message undecryptable under any log that differs from the sender's.

## 8. Pairing (adding a device)

1. Existing device A shows a one-time **pairing secret** `ps` (32 random bytes) as 24 words or `pcsync2:`+b64u QR. `ps` is **not**
   a group key. `pid = HKDF(ps, "paulian-sync/v2/pair-id", 16)` (mailbox name), `mk = HKDF(ps, "paulian-sync/v2/pair-key", 32)`.
2. A writes slot `offer` to `PUT /v2/pair/{pid hex}/offer` on every enabled relay (it only needs one to succeed): `{v:2, gid, relays:[...]}`, sealed as
   `nonce24 || AEAD(mk, nonce, json, aad = "paulian-sync/v2/pair/offer" || pid)`.
3. New device B scans/types the code, reads `offer`, generates its fresh group keys and writes `join`:
   `{v:2, ed:hex, x:hex, name}`: **lowercase hex, 64 chars each, not base64url** (same sealing, slot name `join`). A reader may also accept b64u (older Mac/Windows desktop builds wrote it).
4. Both screens show a **6-digit SAS**: first 4 bytes of `SHA-256("paulian-sync/v2/sas" || gid || joinerEd || joinerX || pid)`
   as u32 mod 10^6, formatted `123 456`. The user confirms they match, then taps **Approve** on A (or Reject). A mismatch means
   somebody else answered the code.
5. On approve A appends an `add` entry with B and writes `welcome {v:2, ok:true, epoch}`; on reject `ok:false`. B then reads the log,
   opens its key package, and joins. The mailbox is write-once per slot and the relay discards it 10 minutes after the first write.
6. The pairing secret is single-use: a second `join` is refused (write-once). Capturing the code later gives nothing.

Because the code is not the group key, a photo of the code is only useful within 10 minutes and still needs the SAS approval on A.

## 9. Client rules the Android implementation must follow

* **Flush before destructive changes.** Leave, stop sync, remove device and rotate first push every pending change to every relay.
  If anything cannot be uploaded the operation stops and reports exactly what is pending (counts per relay); only an explicit
  *force* continues. Only after the flush succeeds: delete the group on the relays (or append a self-`remove`) and **then** forget
  local state. Failures of `DELETE` or removal are surfaced to the user with the relay name, never swallowed.
* **Seal at enqueue.** A change is encrypted when it is queued (the plaintext is not kept longer than needed) and persisted
  before upload; on `409 stale_epoch` the client fetches the log, re-seals and retries.
* **No silent downgrade.** If any configured relay speaks v2, create/join use v2. v1 is used only if every relay is reachable and
  none offers v2 (then it is labelled "legacy"). An unreachable relay never leads to a v1 group.
* **Do not trust one relay.** With several relays, compare log heads; seed a relay that is behind (`POST /log` with `entries[]`);
  report a fork. Seed mode needs the caller to be a member in the state the batch ENDS in, so a device that joined after the
  first 64 log entries cannot seed an empty relay (a 5-year-old group at one rotation per 30 days); an older member can.
* Three consecutive 401/403 responses on a group -> `access_lost` (probably removed); stop syncing and tell the user.
* Secrets: `{groupRoot, edSeed, xSk}` in the platform keystore (Keychain / Windows Credential Manager / Android Keystore);
  everything else (log, chains, outbox) in a sealed file under a keystore key. Wipe key material after use where the platform allows.

### 9.1 Clarifications (agreed between the desktop and Android implementations)

* **Pairing codes.** `pcsync1:`/`pcsync2:` prefixes are accepted by every UI. 24 bare words are ambiguous (a v1 group secret and a v2
  pairing secret look alike), so the client looks up the offer mailbox (`/v2/pair/{pid}/offer`) on its enabled relays: found means v2,
  not found means "expired / unknown" for `pcsync2:` and a legacy v1 join for bare words or `pcsync1:` only if the relay still has `v1: readwrite`.
* **`409 stale_epoch`.** The client fetches the log first. Then EITHER re-seals the queued items for the new epoch OR drops the
  old-epoch items and publishes one fresh snapshot of the local document. Never drop without the snapshot. Both converge, because a
  snapshot is the whole document.
* **A permanently rejected change** (4xx other than 401/408/429/507) is reported (`push_rejected`), removed from the queue for that relay,
  and replaced by one fresh snapshot of the local document, so the other devices never silently miss the edit. Never retry such a batch forever.
* **WebSocket close codes.** `4403` (removed) is a hint only (a relay can send any close code). A removed device is locked out of the log
  too (every signed request answers `401`), so it cannot "read the log to confirm". The confirmation is: the signed log read after a `4403`
  either shows the removal or fails with `401` (not `stale_timestamp` / `replayed_request`). Then THAT relay counts as lost for this device.
  One relay's `4403` alone must not end the group while another enabled relay still accepts this device. `4000` (relay deleted the group)
  marks THAT relay gone. The group ends locally only when every enabled relay is gone or lost (`4000`, confirmed `4403`, or 3 consecutive
  `401`s). Local data is never deleted by any of these.
* **`DELETE /v2/g/{gid}` that answers `404`** counts as already removed. This relay answers `401` for unknown groups (no existence oracle).
* **Orphan member.** If a joiner crashes after the approving device appended it to the log but before it stored its keys, the log has a
  member nobody holds secrets for. That is not a confidentiality risk (the epoch key was sealed to a key pair that no longer exists)
  and the relay cannot know about it. It is cleaned up by removing the unknown device in the device list (which rotates the epoch key). The relay must not prune members.
* **Compaction** is optional for clients: snapshots are published on join, rotation and stale epoch, and the relay prunes snapshot-covered history
  older than 90 days. A client that gets `507` (quota) SHOULD publish a snapshot and call `POST /compact`.

## 10. Retention and relay-side policy (fixes: relay trust for retention)

* v2 groups with no push for 90 days are deleted (daily alarm). Within a group, history older than 90 days **that is covered by a
  snapshot** is pruned. Members may compact at any time with a snapshot.
* Clients treat the relay as a cache: the device that holds a change keeps it until the relay has acknowledged it, and a client
  that still holds the state can write a fresh snapshot and re-seed the membership log of an empty relay. A relay that deletes early only costs availability, never confidentiality.
* The Durable Objects store no IP addresses or user agents; Workers observability (request logs) is disabled by default in `wrangler.toml`; per-IP (Workers Rate Limiting) and per-group token-bucket limits apply. The Cloudflare edge itself necessarily sees client IPs.

## 11. Metadata that remains visible to the relay

The (random) group id, the number of members (log entry), the day (not the time) of each membership change, the time of each
write, the bucketed size (4 KiB ... 1 MiB), which member device (random per-group id) wrote, and the IP address at the TCP level
(not stored). Not visible: titles, content, device names, identities across groups, the pairing secret.
Mitigation: batch writes (clients delay and coalesce uploads, default 1-5 s random), padding, and per-group device keys. See SECURITY.md.

## 12. Deployment and v1 retirement

The relay serves v1 and v2 side by side. v1 (single shared group secret, unauthenticated reads) is the weak design this protocol
replaces; `V1_MODE` controls it:

| `V1_MODE` | v1 reads | v1 writes | v1 group delete |
|---|---|---|---|
| `readwrite` | yes | yes | yes |
| `readonly` (**default**) | yes until `V1_READONLY_UNTIL` (default 2027-02-01T00:00:00Z) | **503 `v1_read_only` + `Retry-After: 900`** (after `V1_READONLY_UNTIL`: 410 `v1_retired`) | **not allowed** (same 503) |
| `off` | no | no | no |

Effect on existing apps: any v1-only client (Android 1.7.0 and 1.8.0 as shipped, desktop builds before this change) can no
longer push when the relay is in `readonly` mode; it must update to a v2 client.

**Why 503 and not 410.** A v1 write refused in `readonly` mode is *temporary from the client's point of view*: the user's edit is
still valid and must reach the other devices after the client upgrades. Measured with the real Android 1.7.0 client code and a test probe: on 503 and 429 the client keeps its queue and retries later; on 410, 400, or a 200 it does not
understand it **drops the outgoing batch** (it records `lastError` and shows pending 0), so the other devices never receive the edit
until some later snapshot. A 410 would therefore cause silent divergence. `readonly` v1 writes (POST, and DELETE of a v1 group)
get `503 {"error":"v1_read_only"}` with `Retry-After: 900`. 410 `v1_retired` is used only when v1 is finished (`off`, or past
`V1_READONLY_UNTIL`), where dropping is no longer a regression. **Client rule:** a v1 client that receives 503 `v1_read_only` (or
410) on a write MUST keep its queue, MUST NOT count the batch as delivered, SHOULD back off for at least `Retry-After`, and SHOULD
show "update required" and offer the v2 upgrade; all local data stays intact. v2-capable clients (desktop, Android 1.9.0) do this. Roll-out order: (1) ship v2 clients, (2) deploy the relay with `V1_MODE=readwrite`, (3) when clients have upgraded
switch to `readonly`, (4) `off`.

## 13. Test vectors

`sync_v2_vectors.json` covers: key derivation from seeds, device ids and relay gid; signed-request canonical strings for GET, POST,
DELETE and a WebSocket auth frame (with signatures and `Authorization` headers) and query canonicalisation; padding buckets and an
inner padding example with a non-canonical negative; ratchet steps 0..4 and out-of-order use; an epoch-key package; a six-entry
membership log with every hash and negative cases (`bad_signature`, `bad_index`, `bad_prev`, `bad_remove`); two chained
envelopes opened by the receiver; and pairing (words, QR, `pid`, `mk`, SAS, a sealed slot). All random inputs (nonces, epoch keys,
roots) are given explicitly, so a Kotlin test can reproduce every output without our RNG.
