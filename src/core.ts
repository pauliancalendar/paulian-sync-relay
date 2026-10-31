/**
 * Shared helpers of the Paulian Sync relay: the token bucket and the JSON/CORS response helpers.
 * Platform-neutral: uses only the Fetch API Request/Response, so the same file runs in Cloudflare Workers and Node 22+.
 * The protocol itself (protocol 2, the only one) is in proto2.ts and core2.ts.
 *
 * CANONICAL COPY: relay/src/core.ts. relay-selfhost/src/core.ts is a vendored copy
 * (scripts/vendor-relay-core.sh); never edit the copy by hand.
 */

export class TokenBucket {
  private tokens: number;
  private last: number;
  constructor(private capacity: number, private refillPerSec: number, now = Date.now()) {
    this.tokens = capacity; this.last = now;
  }
  /** Returns 0 if allowed, otherwise ms to wait. */
  take(n = 1, now = Date.now()): number {
    this.tokens = Math.min(this.capacity, this.tokens + ((now - this.last) / 1000) * this.refillPerSec);
    this.last = now;
    if (this.tokens >= n) { this.tokens -= n; return 0; }
    return Math.ceil(((n - this.tokens) / this.refillPerSec) * 1000);
  }
}

export function corsHeaders(): Record<string, string> {
  return {
    'access-control-allow-origin': '*',
    'access-control-allow-methods': 'GET, POST, DELETE, OPTIONS',
    'access-control-allow-headers': 'content-type',
    'access-control-max-age': '86400',
  };
}

export function json(body: unknown, status = 200, extra: Record<string, string> = {}): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'content-type': 'application/json', 'cache-control': 'no-store', ...corsHeaders(), ...extra },
  });
}

export function err(status: number, code: string, extra: Record<string, string> = {}): Response {
  return json({ error: code }, status, extra);
}
