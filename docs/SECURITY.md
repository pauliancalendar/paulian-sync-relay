# Paulian Sync: security model

Applies to sync protocol v2 (`PROTOCOL_V2.md`) as implemented in the relay and the Paulian Calendar apps. Sync is optional and off by default; with sync off nothing is created and no network call is made.

## 1. What is protected, from whom

| Asset | Protected against |
|---|---|
| Content (events, diary, images, titles, device names) | The relay operator, network observers, anyone who finds a group id or relay URL, a removed device (for later epochs) |
| Group membership | Unauthorised joining: a pairing code alone gives no keys; a member must approve, after comparing a 6-digit code |
| Integrity and order of history | A relay (or attacker) that edits, reorders, replays or forks data: everything is signed, chained and bound to the epoch |
| Availability | Only partly (section 5) |

**Attackers considered:** (A) passive/active network attacker; (B) honest-but-curious or malicious relay; (C) someone who learns the
relay URL and group id (screenshot, log line, shoulder-surfing); (D) someone who photographs or intercepts a pairing code;
(E) a lost or stolen device, or malware on a device; (F) a former member; (G) an attacker with a copy of the app's data folder.
**Out of scope:** a fully compromised device while the app is running and unlocked (it can read what the user can read), a malicious
member who is still in the group (members are equals), traffic analysis by someone who sees both sides of a TLS connection,
denial of service by the relay.

## 2. The four reported weaknesses and what fixes them

### 1. Unauthenticated relay reads (the earlier, now removed protocol: knowing the group id was enough to download all ciphertext)
* The relay-facing group id is derived from a random `groupRoot` that only members hold (`HKDF`, not a hash of a public key).
* **Every** request and the WebSocket open must be signed by a device that is in the verified membership log; timestamp +/- 5 min,
  single-use nonce, body hash in the signed string. Non-members, unknown groups and removed devices all receive the same `401`.
* Pairing no longer hands out a group secret. The 24 words / QR are a **one-time** mailbox secret (10 minutes, write-once) and
  the new device gets keys only after an existing member approves it by comparing a 6-digit code.
* Per-group, per-IP rate limits (including a cap on the health page and on new group or pairing allocations), 3 MiB body cap, 64 MiB / 50 000-change group quota, 16 sockets per group.
* From relay 1.3.0 an optional per-relay access key (`RELAY_ACCESS_SECRET`, sent as `x-paulian-relay-key`) stops anyone
  who only knows or guesses the URL from using the relay or reading its health page. It is not a second encryption key:
  calendar data is still encrypted on the devices. A relay with no key configured keeps the previous behaviour.
* Unknown group ids do not create empty Durable Object storage. A guessed address can still reach the Worker (it is a
  public HTTPS URL). The pairing mailbox id is 128 random bits from the pairing code; when an access key is configured,
  every pairing request must also prove knowledge of that code (an Ed25519 key derived from it), so knowing or logging
  the mailbox id is not enough to read or write the slots.
* Tests: relay API suite (unauthenticated, wrong key, replayed nonce, skewed clock, removed member, tampered body); client tests for 401 handling.

### 2. Metadata exposure
* Sizes: every blob is padded to a power of two (4 KiB ... 1 MiB) with canonical zero padding; the relay cannot see how big a change was.
* Timing: no timestamps in envelopes or log entries beyond a **day** (floored to 86 400 s); clients batch and delay uploads by a random 1-5 s.
* Device identity: keys and device ids are per group, so devices cannot be linked across groups; device names are only inside encrypted
  pairing messages; the relay sees random ids.
* Group longevity: v2 groups are deleted after 90 days idle and history covered by a snapshot is pruned after 90 days.
* Members can add several relays so no single operator sees everything.
* **Still visible** (honest list): the group id, member count, the day of each membership change, the time of each write, which
  (random) device id wrote, the coarse size bucket, and the client IP at the network level. Padding costs bandwidth: a tiny change uploads 4 KiB.

### 3. Relay trust: dropping, delaying, truncating, retaining
* Each device's envelopes form a hash chain (`prev` = hash of the device's previous envelope) and indices are consecutive, so a
  **dropped or delayed change in the middle is detected** (gap warning after 10 minutes) and a **forked history** (different data shown
  to different devices) is detected (`fork` warning).
* The membership log is hash-chained and signed; clients keep their own copy, compare heads across relays, and **seed** a relay that is
  behind. A relay cannot invent members, hide a removal, or roll the group back without detection by a client that has seen the newer log.
* Old data: the relay can drop or refuse it, but cannot read or alter it; devices keep their local copy and can rebuild a relay
  (log seeding, fresh snapshot).
* Deletion: the relay's 90-day retention is announced; clients never rely on it for correctness. `DELETE /v2/g/{gid}` is a real delete of
  the group's data. **A relay can ignore a delete request** (nothing a client can do cryptographically); ciphertext it kept stays
  unreadable once all members' keys are gone, and later epochs are unreadable to anyone who was removed.
* Correlation across groups: unlinkable ids and keys per group; the relay can still correlate by IP address and timing.
* Flush-before-leave: leaving, stopping sync, removing a device and rotating keys first upload everything pending or tell the user
  exactly what is still pending; deletion/removal errors are always shown (never swallowed).

### 4. No forward secrecy / key ratchet, rotation, revocation, post-compromise security
* Per-sender **hash ratchet**: message keys are one-way derived and used once. A device that leaks its current chain state exposes only
  messages it has not yet consumed in that epoch; already-consumed keys are wiped and cannot be recomputed (forward secrecy within an epoch).
* **Epochs.** Each membership entry (add, remove, rotate) carries a fresh random epoch key delivered only to the current members.
  Removing a device or rotating gives **new keys the removed/compromised device never receives** (post-compromise security after the
  next rotation), and a new device cannot decrypt older epochs.
* Rotation happens on removal, on demand ("Rotate keys"), when a member leaves without deleting, and automatically after 30 days.
* Revocation is cryptographic and enforced by the relay: a removed device's signed requests are refused and its socket is closed.
* There is no long-lived group key that decrypts everything (the removed earlier protocol had one secret S that decrypted all history and all future data).

## 3. Implementation notes

* libsodium (`libsodium-wrappers-sumo`) for Ed25519, `crypto_box`, XChaCha20-Poly1305 and **`randombytes_buf`** (OS CSPRNG) for every key,
  nonce, id, pairing secret and the upload-batching jitter. `Math.random` appears only in the reconnect back-off (not security
  relevant); `tests/sync/core2/hygiene.test.ts` fails if it shows up anywhere else in the v2 code.
* Nonces are 24 random bytes (XChaCha: collision-safe); message keys are used once so a nonce never repeats under a key.
* Signature is verified before any ratchet key is consumed; padding is canonical; AAD binds group id, header and the epoch start hash.
* Secrets are held in `Uint8Array`s and wiped (`sodium.memzero`-style fill) after use: ratchet keys, chain keys of old epochs, skipped
  keys, pairing secrets. JavaScript strings (words, QR text, base64) cannot be wiped; they are kept only while the code dialog is open.
  On the Rust side keychain values are held in `Zeroizing` buffers; the value returned to the webview crosses IPC as a normal string.
* The device keys `{groupRoot, edSeed, xSk}` live in the OS keychain (macOS Keychain / Windows Credential Manager) under
  `paulian.sync-v2.keys.v1`; the log, chains and outbox are in a file sealed (XChaCha20-Poly1305) with a different keychain key.
  Keychain names are allow-listed in Rust; sync files have fixed names and a 64 MiB cap and atomic writes.
* Fail closed: any parse/verification error rejects the item; unknown protocol versions are refused; there is no older protocol to fall back to.

## 4. Device compromise: what an attacker gets

| Situation | Exposure |
|---|---|
| Lost device, OS account locked | Nothing (keys in the keychain, files sealed) |
| Attacker with the app data folder only | Ciphertext only (local key is in the keychain) |
| Attacker with folder **and** keychain (full account compromise) | Current epoch's chain state and everything the app can read; remove the device from another device: after the removal/rotation they get nothing new |
| Malware while the app runs | All data the user can see; cannot be prevented by sync design |
| Former member | Everything it had already received; nothing from epochs after its removal |

Immediately after losing a device, use *Devices -> Remove* on another device (it rotates the key). If no other device exists, stop
sync with "delete from relays".

## 5. Residual risks (honest)

1. **Single-relay tail truncation:** with one relay, dropping the newest changes is indistinguishable from "nothing new" until a later
   change arrives (then a gap or fork is shown). Use two relays for stronger detection.
2. **Members are equals:** any member can remove others or delete the group. There is no admin role or quorum.
3. **A compromised member sees its epoch onward while it is a member.** Ratchets limit the past, rotation limits the future, but
   neither helps while the attacker is a member that nobody has removed. Automatic rotation is only every 30 days.
4. **Relay availability:** a relay can refuse service, delay (detected as a gap only later), or ignore deletes. A removal made while
   the relay is down needs the user's *Remove anyway* and is not effective until the relay is reachable (the relay can delay revocation).
5. **The earlier protocol is gone.** Relay 1.2.0 and current apps no longer speak it. Data an older relay still holds in the old format is
   deleted when its owner updates to relay 1.2.0 (Durable Object migration `v3`); v2 groups are unaffected.
6. **Metadata** listed in section 2/2 remains; the relay (and Cloudflare) see IPs, write timing, member count and size buckets.
7. **No recovery phrase in v2.** Losing every device loses the group (the encrypted backup file remains the way to keep data).
8. **Outbox plaintext:** queued changes are sealed per change, but the sealed sync file contains the outbox; compromise of file + keychain exposes it.
9. **Crash between relay accept and local commit of a membership change** can leave a device behind by one epoch (`epoch_lost` warning);
   it recovers by re-reading the relay's log and, if it cannot, must be re-added.
10. **Leaving without deleting** relies on the remaining members rotating; until they do, the leaver's keys still work for that epoch.
11. JavaScript memory is garbage-collected: copies of strings and decrypted data cannot be guaranteed wiped.
12. The pairing code is secret for 10 minutes; a person who gets it within that window and a matching 6-digit code can be approved by a distracted user. Compare the digits.
13. The relay URL is reachable on the public internet, random name or not. The access key hides the health page and
    blocks group requests from strangers. Pairing slots do not use that key (so a joining device can read the offer
    that carries it) but, when the key is configured, they do require a proof derived from the pairing secret. The
    pairing id is 128 random bits; empty pairing objects are not persisted.
14. Desktop WebSockets cannot send custom headers, so the access key travels in the first auth frame (`k`) after the
    socket opens, never in the URL. Until that frame is accepted the relay stores nothing and sends nothing. Request
    logs are off by default; even if they were turned on, they would not contain the access key or a ticket.
15. A random Worker name stops casual scanning of a well-known name; it is not a secret. The access key and the
    membership signatures are what stop misuse.

## 6. Reporting

Security issues in the relay or apps: use the **Security** tab of this repository (*Report a vulnerability*) so it stays private; do not post exploit details publicly before a fix.
