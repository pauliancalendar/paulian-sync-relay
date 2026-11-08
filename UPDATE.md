# Update your Paulian sync server

Paulian Calendar tells you when a newer version of your sync server is available ("An update is available for your sync
server"). Updating takes about a minute. **Your synced data stays where it is**: an update replaces the program, not the
stored (encrypted) calendar data, and your devices keep working during it.

You do not have to update right away when the app says an update is *available*. If the app says sync is *paused until
you update*, sync stays off until you do this once.

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

## Easiest way: replace the files in your copy (no software to install)

When you first pressed *Deploy to Cloudflare*, Cloudflare made **your own copy** of this project in your GitHub or GitLab
account. Cloudflare rebuilds and redeploys your server every time that copy changes. So to update, put the new files into your copy:

1. Open this project's page: <https://github.com/pauliancalendar/paulian-sync-relay>. Press **Code → Download ZIP** and unzip it.
2. Open **your copy** on GitHub (or GitLab). If you do not remember where it is, open the Cloudflare dashboard →
   *Workers & Pages* → your server → *Settings* → *Build* and follow the link to the repository.
3. In your copy, replace the files with the new ones: delete the old `src` and `test` folders, then use
   **Add file → Upload files** and drag in the new `src` and `test` folders and the files `package.json`,
   `package-lock.json`, `tsconfig.json` and `wrangler.toml` from the unzipped folder. Then press **Commit changes**.
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
