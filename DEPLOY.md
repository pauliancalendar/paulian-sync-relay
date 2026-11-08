# Deploy your own Paulian sync relay (about 5 minutes, free)

You need: a web browser, an email address you can confirm, a free Cloudflare account, and a GitHub or GitLab
account (Cloudflare copies this project into it so you keep a copy you control). No credit card is needed for the
Workers Free plan. You do not need to install anything if you use the button below.

The app (Sync → Set up your sync server) shows a **Worker name** and an **access key** for you to copy. Use those
when Cloudflare asks, so you do not have to invent them yourself.

## What you will do

1. Open the Deploy to Cloudflare page from the README or from the app.
2. Sign in to Cloudflare (or create a free account and confirm the email they send).
3. Connect GitHub or GitLab when asked, so Cloudflare can save your own copy of this project.
4. On the setup page, set the Worker name to the unique name from the app and paste the access key if you are
   asked for a secret named `RELAY_ACCESS_SECRET`. Leave other fields at their defaults unless you have a
   reason to change them.
5. Start the deploy and wait until it finishes.
6. Copy the address that ends in `.workers.dev`, paste it into Paulian Calendar with the same access key, and
   press *Check and continue*.

## The Cloudflare screens, step by step

Cloudflare’s pages change their wording from time to time. If a label does not match exactly, look for the
same idea (sign in, connect a Git account, Worker name, secret, deploy).

### 1. Sign in

Press **Deploy to Cloudflare** in the README or in the app (Sync → Set up your sync server → *Open Cloudflare*).
Sign in to Cloudflare, or create a free account. Confirm the email Cloudflare sends you if this is your first time.

### 2. Connect GitHub or GitLab

Cloudflare clones this project into **your** GitHub or GitLab account so the copy is yours. Public GitHub.com and
GitLab.com accounts work; self-hosted Git servers do not (that is a Cloudflare limitation).

When you are asked to connect GitHub or GitLab, sign in and allow the connection. If you see a choice to create
a **private** repository for your copy, keep that selected so your copy is not listed publicly.

### 3. The setup page (the page with several fields)

Cloudflare describes this as a single setup page where you can customize details such as the **repository name**,
the **Worker name**, and required resource names. You may also be asked for secrets listed in this project.

- **Worker name:** do not leave the default if the app showed you a name. Paste the name from Paulian Calendar.
  It looks like `paulian-calendar-sync-` followed by 8 lowercase letters or digits (for example
  `paulian-calendar-sync-k7m2nq9p`). That name becomes the first part of your address.
- **Repository name:** you can leave the suggested name, or match the Worker name. Either is fine.
- **Other resource names:** leave them as they are. This project already includes the storage it needs
  (Durable Objects). Cloudflare provisions those from the configuration file; you do not create them by hand.
- **Build or deploy commands:** if those fields appear, you can accept what Cloudflare filled in.
- **`RELAY_ACCESS_SECRET`:** if the page asks for this secret, paste the access key from the app. Treat it as a
  secret, not a plaintext environment variable. If the page does not ask, you will add it after the deploy
  (next section).

Then start the deploy and wait until the build finishes.

### 4. Your `workers.dev` subdomain (first time on Cloudflare only)

If you are asked to choose a *workers.dev subdomain*, pick any name you will recognize. This becomes the last
part of every Worker address on your account. Your relay’s address will look like
`https://<worker-name>.<your-subdomain>.workers.dev`.

Later, that subdomain is the “Your subdomain” setting on the Workers page in the Cloudflare dashboard.

### 5. If you still need to add the access key

The access key is stored as a Worker **secret** (the value is hidden afterwards). If you did not paste it on the
setup page:

**In the dashboard:** open the Workers page (*Workers & Pages* in Cloudflare’s current docs — the name in the
sidebar can vary). Open your Worker → **Settings** → **Variables and Secrets** → **Add**. Choose the type
**Secret**, set the variable name to `RELAY_ACCESS_SECRET`, paste the access key from the app as the value, and
press **Deploy** to apply it.

**From a command line** (after `npx wrangler login`):

```bash
npx wrangler secret put RELAY_ACCESS_SECRET
```

When asked, paste the same access key. This command updates the Worker; it does not change your stored calendar
data. Do not put the access key in `wrangler.toml`.

### 6. Copy your relay address

It is shown when the deploy finishes. Later, find it in the Cloudflare dashboard: open your Worker → **Settings**
and look for the `workers.dev` entry (under *Domains & Routes* on current docs). Copy the `https://…workers.dev`
address with nothing after it.

A new deploy that used the name from the app looks like
`https://paulian-calendar-sync-k7m2nq9p.your-name.workers.dev`. Older servers may still be called
`paulian-sync-server` or `paulian-sync-relay`; those names keep working.

### 7. Paste it into Paulian Calendar

Open Sync → Set up your sync server, paste the address and the same access key, and press *Check and continue*.
Create your sync code. When you add your next device, scanning the QR code also hands over the address and the
access key. If you type the 24 words instead, also type your relay address; the access key arrives with the
pairing offer, so you do not type it again.

## Command-line alternative

If you prefer not to use the button:

```bash
git clone https://github.com/pauliancalendar/paulian-sync-relay
cd paulian-sync-relay
npm ci
node scripts/setup-relay.mjs    # writes a random Worker name into wrangler.toml and prints an access key
npx wrangler login
npx wrangler deploy
npx wrangler secret put RELAY_ACCESS_SECRET   # paste the access key that was printed
```

`setup-relay.mjs --print` shows a name and key without changing any file.

## Troubleshooting

| Problem | What to do |
|---|---|
| The app says "That address did not answer" | Check the address for typos and that the deploy finished. Check your internet connection and any VPN or firewall. |
| The app says the server needs an access key | Paste the access key you set as `RELAY_ACCESS_SECRET`. If you have not added that secret yet, add it (section 5) and try again. |
| The app says the access key was not accepted | Copy the key again. Do not add spaces. If you generated a new key in the app after deploying, use the key you actually saved on the Worker. |
| The app says "This is not a Paulian relay" | The address is some other Worker, or the access key is missing so the health page will not identify itself. Use the Worker you deployed from this project. |
| The app says it must end in `.workers.dev` | Use the address Cloudflare gave you. Custom domains are not supported yet. |
| Build failed on Cloudflare | Open the build log in the dashboard. Retry the deploy. Make sure the Durable Objects feature is allowed on your plan (Workers Free supports the SQLite kind used here). |
| I deployed twice and have two relays | Use one. Delete the other in the dashboard (open the Worker → *Settings* → *Delete*). |
| I updated my files and sync stopped | You may have changed the Worker name. Changing `name` in `wrangler.toml` creates a new, empty server. Put the old name back and deploy again. |

## Updating, moving and deleting

* **Update:** see [UPDATE.md](UPDATE.md). Paulian Calendar also tells you when an update is available. Your sync data stays in place.
* **Delete everything:** delete the Worker in the Cloudflare dashboard (open the Worker → *Settings* → *Delete*).
  That removes all stored (encrypted) data. Your devices keep their local calendars.
* **Data retention:** a sync group with no activity for 90 days (`RETENTION_DAYS_V2`) is deleted from your relay.

## Is it private? What does the relay see?

It stores encrypted, padded blobs it cannot read, plus routing data: an anonymous group id, device ids, sizes and
a coarse day for membership changes, and the time of each write. Request logs are off. It is **your** Cloudflare
account, so the developers of Paulian Calendar receive none of this. Cloudflare, as your hosting provider, handles
the network traffic like for any website you host there.

If you set an access key, strangers who only guess the address cannot use the relay or read its health page. Your
devices still prove they belong to the group with keys that never leave them. Guessing the address was never enough
to read a calendar.

## Costs and limits

The Workers Free plan includes 100,000 Worker requests per day and, for SQLite Durable Objects, 100,000 Durable
Object requests and 100,000 rows written per day (plus a large number of row reads and several gigabytes of stored
data). Those included amounts are enough for a typical person’s own devices; the rows-written limit is the one you
would reach first. Daily free limits reset at 00:00 UTC. On the Free plan, going past a limit makes further
operations of that type fail until the next day — it does not start a bill. You only pay if you choose a paid
Workers plan. Limits can change: <https://developers.cloudflare.com/workers/platform/limits/> and
<https://developers.cloudflare.com/durable-objects/platform/pricing/>.
