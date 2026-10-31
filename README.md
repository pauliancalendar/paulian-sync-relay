# Paulian Calendar sync relay (run your own, free)

Paulian Calendar syncs your calendar and diary between your devices with end-to-end encryption.
The **relay** is the small server that passes the encrypted changes between your devices. It cannot read
anything. **You run your own relay on your own free Cloudflare account**, so nobody else, including the
makers of the app, ever receives your sync data.

[![Deploy to Cloudflare](https://deploy.workers.cloudflare.com/button)](https://deploy.workers.cloudflare.com/?url=https://github.com/pauliancalendar/paulian-sync-relay)

1. Press the button and follow Cloudflare's steps (free account, no card needed for the Workers Free plan).
2. Copy the address of your new Worker. It ends in `.workers.dev`.
3. Paste it into Paulian Calendar: **Sync → Set up your relay**.

Step-by-step guide with troubleshooting: **[DEPLOY.md](DEPLOY.md)**. Updating a relay you already run: **[UPDATE.md](UPDATE.md)**.

## What is in here

* Cloudflare Worker (`src/index.ts`) plus Durable Objects (one per sync group, SQLite storage, WebSocket hibernation).
* `wrangler.toml`: the deploy template. No account name, no route and no domain, nothing to edit.
  `RETENTION_DAYS_V2=90`.
* No secrets and no environment variables you must fill in.
* `docs/PROTOCOL_V2.md` (wire protocol) and `docs/SECURITY.md` (threat model).

The Paulian Calendar apps only connect to **Cloudflare-hosted** relays on `*.workers.dev`.

## Develop and test

```bash
npm ci
npm run typecheck
npm test               # unit tests + the API suite against a real local `wrangler dev`
npx wrangler dev       # local relay on http://127.0.0.1:8787
npx wrangler deploy --dry-run --outdir /tmp/relay-out   # validate the config, deploys nothing
```

## Free-plan limits

| Cloudflare Workers Free limit (per day) | Rough meaning |
|---|---|
| 100,000 Worker requests | far more than a personal calendar needs |
| 100,000 Durable Object requests | the same requests, forwarded |
| 100,000 Durable Object rows written | the first limit you would hit: roughly 48 typical devices |

Check the current numbers at <https://developers.cloudflare.com/durable-objects/platform/pricing/> and
<https://developers.cloudflare.com/workers/platform/limits/>.

## Privacy

The relay stores only encrypted, padded blobs plus the routing data it needs: an anonymous group id, device ids,
sizes and times. It sees your devices' IP addresses like any web server. Workers request logs are off
(`[observability] enabled = false`). See `docs/SECURITY.md`.

## Health check

`GET /v2/health` returns `{"ok":true,"service":"paulian-sync-relay","relayVersion":"1.2.0","protocol":2,"impl":"cloudflare-worker",...}`.
The apps use it to check that an address you paste is a Paulian relay, and `relayVersion` to tell you when an update is available.

## License

Licensed under the [Apache License, Version 2.0](LICENSE). See [NOTICE](NOTICE). You may use, copy and modify this sync server, including for your own deployment, under the terms of that license. It is provided "as is", without warranties.
