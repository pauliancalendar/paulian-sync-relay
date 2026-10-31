import { describe, expect, it } from 'vitest';
import { TokenBucket, parseGroupPath, b64uDecode, b64uEncode, parseEnvelopeHeader } from '../src/core';

describe('relay core', () => {
  it('token bucket allows a burst then refills', () => {
    const b = new TokenBucket(3, 1, 0);
    expect([b.take(1, 0), b.take(1, 0), b.take(1, 0)]).toEqual([0, 0, 0]);
    expect(b.take(1, 0)).toBe(1000);
    expect(b.take(1, 1000)).toBe(0);
  });
  it('parses group paths', () => {
    expect(parseGroupPath('/v1/groups/abc/changes')).toEqual({ gid: 'abc', sub: '/changes' });
    expect(parseGroupPath('/v1/groups/abc')).toEqual({ gid: 'abc', sub: '' });
    expect(parseGroupPath('/v1/other')).toBeNull();
  });
  it('base64url and header parsing are strict', () => {
    const b = new Uint8Array([1, 2, 250, 255]);
    expect(b64uDecode(b64uEncode(b))).toEqual(b);
    expect(b64uDecode('a+/=')).toBeNull();
    expect(parseEnvelopeHeader(new Uint8Array(10))).toBeNull();
  });
});
