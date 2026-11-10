# Update your Paulian sync server

Paulian Calendar tells you when a newer version of your sync server is available ("An update is available for your sync
server"). Updating takes about a minute. **Your synced data stays where it is**: an update replaces the program, not the
stored (encrypted) calendar data, and your devices keep working during it.

You do not have to update right away when the app says an update is *available*. If the app says sync is *paused until
you update*, sync stays off until you do this once.

## Update from the app (about a minute, after a one-time setup)

When Paulian Calendar shows **"Your sync server has an update"**, press **Update on GitHub**. The app opens the
*Update my server* page of **your copy** of this project on GitHub. There:

1. Press **Run workflow**.
2. Press the green **Run workflow** button in the small box that opens.
3. Go back to the app. It shows *Waiting for your server to update…* and tells you when it is done (usually 1 to 3 minutes).

The first time, the app asks for the address of your copy on GitHub (for example `https://github.com/your-name/paulian-sync-relay`).
If you do not remember it: Cloudflare dashboard → *Workers & Pages* → your server → *Settings* → *Build* → the repository link.

**What the update does:** it downloads the newest Paulian sync server release, checks that it really was signed by
Paulian Calendar and that every file is exactly the signed one, then puts the new files into your copy. It keeps your
server's name and your settings, never touches your access key or your stored data, and refuses to go back to an older
version. Cloudflare then rebuilds your server as usual. If any check fails, nothing is changed.

**One-time setup (only if your copy does not have "Update my server" yet).** Copies made before this feature existed
do not have it. Do one update by hand with the steps below, and include the hidden `.github` folder:
the easiest way is, in your copy on GitHub, **Add file → Create new file**, type the name
`.github/workflows/update-server.yml`, paste the content of
[that file](.github/workflows/update-server.yml) from this project, and press **Commit changes**. Also copy the
`scripts` folder. After that, every later update is the three steps above.

The workflow file itself is kept short and rarely changes, because GitHub does not let a workflow change workflow
files. All the update logic is in `scripts/update-server.mjs`, which each update refreshes.

## Which version do I have?

Open `https://<your address>/v2/health` in a browser (your address is the one ending in `.workers.dev`). Look for
`"relayVersion":"..."`. If that line is missing, you have version 1.0.0.

| Version | What changed |
|---|---|
| 1.3.0 | Optional access key (`RELAY_ACCESS_SECRET`) so a guessed address cannot use the relay; health page is rate-limited and, with a key set, no longer answers strangers; unknown group ids no longer create empty storage; new deploys should use a random `paulian-calendar-sync-` name; the access key is sent as a request header or inside the first live-sync message, never in the address; when the key is set, pairing requests must prove knowledge of the pairing code so a stranger who only sees the mailbox id cannot touch it. Your existing name and data stay as they are if you keep the same Worker name. After you set an access key, paste it in the app on each device you already use (Sync → Advanced), or add a device again so the key is handed over automatically. |
| 1.2.0 | The old sync protocol is removed (`/v1/...` now answers 404). Updating deletes any data your server still holds in that old format; calendars and diaries synced with the current protocol are not affected. Apps now check `/v2/health`. |
| 1.1.0 | The health page now shows `relayVersion`, so the app can tell you when an update is available. |
| 1.0.0 | First public version. |

The newest version is the one in [`package.json`](package.json) in this repository.

## By hand: replace the files in your copy (no software to install)

When you first pressed *Deploy to Cloudflare*, Cloudflare made **your own copy** of this project in your GitHub or GitLab
account. Cloudflare rebuilds and redeploys your server every time that copy changes. So to update, put the new files into your copy:

1. Open this project's page: <https://github.com/pauliancalendar/paulian-sync-relay>. Press **Code → Download ZIP** and unzip it.
2. Open **your copy** on GitHub (or GitLab). If you do not remember where it is, open the Cloudflare dashboard →
   *Workers & Pages* → your server → *Settings* → *Build* and follow the link to the repository.
3. In your copy, replace the files with the new ones: delete the old `src` and `test` folders, then use
   **Add file → Upload files** and drag in the new `src`, `test`, `scripts` and `docs` folders and the files `package.json`,
   `package-lock.json`, `tsconfig.json`, `release-notes.json` and `wrangler.toml` from the unzipped folder. Then press **Commit changes**.
   (To add *Update my server* for next time, also create `.github/workflows/update-server.yml` as described above.)
4. Wait about a minute. In the Cloudflare dashboard, *Workers & Pages* → your server → *Deployments* shows the new
   deployment as it finishes. Then open `https://<your address>/v2/health` again: `relayVersion` should show the new number.

Do **not** rename your server and do **not** delete it. A server with a different name is a new, empty server, and your
devices would have to be set up on it again. Keep the same name you already use (`paulian-sync-server` for many servers,
`paulian-sync-relay` for some older ones, or `paulian-calendar-sync-` plus eight characters if you chose a unique name).
The name is the `name = "…"` line at the top of `wrangler.toml`. The new file may still say `paulian-sync-server`; if
your server has a different name, change that line back to your name after you copy the new file in, so the update goes
to your existing server.

## If you are comfortable with a command line

```bash
git clone https://github.com/pauliancalendar/paulian-sync-relay
cd paulian-sync-relay
npm ci
npx wrangler login
npx wrangler deploy --name paulian-sync-server   # use the exact name of your existing server (an older one may be paulian-sync-relay; a newer one may be paulian-calendar-sync-________)
```

Using the same server name updates your existing server and keeps its data.

## After updating

Open Paulian Calendar → Sync. The update note disappears the next time the app checks your server (within a few minutes, or
press *Sync now*). If it does not, see the table in [DEPLOY.md](DEPLOY.md).

## Update did not work?

* Check the build log in the Cloudflare dashboard (*Workers & Pages* → your server → *Deployments*).
* Make sure you replaced `src` completely (old files left behind can cause a build error).
* Your data is safe: the calendar and diary on your devices are never touched by an update.
* Going back to an older version of the files is not supported after updating to 1.2.0 or later (the 1.2.0 update removes the storage the old
  protocol used). If something is wrong, fix the build and redeploy the current version.
* Adding an access key is optional when you update. Until you set `RELAY_ACCESS_SECRET`, the server keeps accepting
  requests the old way. Once you set it, every device must send it.

## Publishing a release (for the Paulian Calendar publisher only)

Releases are signed offline with an Ed25519 key that never leaves the publisher's computer and is never committed.

1. Once: `node scripts/sign-manifest.mjs --generate-key ~/PaulianSigning/relay-signing.pem` (outside this folder).
   Back the file up offline. Paste the printed public key into `PUBLISHER_PUBLIC_KEY` in `scripts/update-server.mjs`
   and into the apps (`RELAY_PUBLISHER_PUBLIC_KEY`).
2. Each release: bump `package.json`, `RELAY_VERSION` in `src/core2.ts` and `release-notes.json` (plain-language notes,
   `security: true` for security fixes), commit, and tag `vX.Y.Z`.
3. `node scripts/build-release.mjs` writes `dist/relay-manifest.json`;
   `node scripts/sign-manifest.mjs --key ~/PaulianSigning/relay-signing.pem dist/relay-manifest.json` writes the `.sig`.
4. Push the commit and tag, create the GitHub release `vX.Y.Z`, and attach `relay-manifest.json` and
   `relay-manifest.json.sig`. Upload the same two files as `relay/latest.json` and `relay/latest.json.sig` to the
   downloads site, which the apps read for the "What's new" card.
