# Deploy your own Paulian sync relay (about 5 minutes, free)

You need: a web browser, an email address, and a GitHub or GitLab account (Cloudflare copies this project into it so
you keep a copy you control). No credit card is needed for the Workers Free plan. You do not need to install anything.

## Steps

1. **Press "Deploy to Cloudflare"** in the README (or in the app: Sync → Set up your relay → *Deploy my relay on Cloudflare*).
2. **Sign in to Cloudflare**, or create a free account.
3. **Connect GitHub or GitLab** when Cloudflare asks. It creates your own copy of this project there.
4. **Leave the defaults** (project name `paulian-sync-server`, no variables or secrets to fill in) and press **Deploy**.
   Wait until the build finishes.
5. **First time on Cloudflare only:** if you are asked to choose a *workers.dev subdomain*, pick any name. Your relay's
   address will be `https://paulian-sync-server.<your-subdomain>.workers.dev`.
6. **Copy your relay address.** It is shown when the deploy finishes. Later, find it in the Cloudflare dashboard:
   *Workers & Pages* → your Worker → *Settings* → *Domains & Routes* (the `workers.dev` entry). The wording of Cloudflare's pages can change slightly.
7. **Check it:** open `https://<your address>/v2/health` in a browser. You should see text containing
   `"ok":true` and `"service":"paulian-sync-relay"`.
8. **Paste the address into Paulian Calendar** (Sync → Set up your relay) and press *Check and use this relay*.
9. Create your sync code. When you add your next device, scanning the QR code on it also sets up the relay there.
   If you type the 24 words instead, also type your relay address.

## Troubleshooting

| Problem | What to do |
|---|---|
| The app says "That address did not answer" | Open `https://<address>/v2/health` in a browser. If that works, check your internet connection and any VPN or firewall. |
| The app says "This is not a Paulian relay" | The address is some other Worker. Copy the address of the `paulian-sync-server` Worker. |
| The app says it must end in `.workers.dev` | Use the address Cloudflare gave you. Custom domains are not supported yet. |
| Build failed on Cloudflare | Open the build log in the dashboard. Retry the deploy. Make sure the Durable Objects feature is allowed on your plan (Workers Free supports the SQLite kind used here). |
| I deployed twice and have two relays | Use one. Delete the other in the dashboard (*Workers & Pages* → the Worker → *Settings* → *Delete*). |

## Updating, moving and deleting

* **Update:** see [UPDATE.md](UPDATE.md). Paulian Calendar also tells you when an update is available. Your sync data stays in place.
* **Delete everything:** delete the Worker in the Cloudflare dashboard. That removes all stored (encrypted) data.
  Your devices keep their local calendars.
* **Data retention:** a sync group with no activity for 90 days (`RETENTION_DAYS_V2`) is deleted from your relay.

## Is it private? What does the relay see?

It stores encrypted, padded blobs it cannot read, plus routing data: an anonymous group id, device ids, sizes and
timestamps. Request logs are off. It is **your** Cloudflare account, so the developers of Paulian Calendar receive none of
this. Cloudflare, as your hosting provider, handles the network traffic like for any website you host there.

## Costs and limits

The Workers Free plan allows 100,000 Worker requests, 100,000 Durable Object requests and 100,000 Durable Object
rows written per day. That is enough for roughly 48 typical devices (the rows-written limit is reached first), which is
far above one person's devices. Limits can change: <https://developers.cloudflare.com/workers/platform/limits/>.
