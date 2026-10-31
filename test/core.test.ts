import { describe, expect, it } from 'vitest';
import { TokenBucket } from '../src/core';

describe('relay core', () => {
  it('token bucket allows a burst then refills', () => {
    const b = new TokenBucket(3, 1, 0);
    expect([b.take(1, 0), b.take(1, 0), b.take(1, 0)]).toEqual([0, 0, 0]);
    expect(b.take(1, 0)).toBe(1000);
    expect(b.take(1, 1000)).toBe(0);
  });
});
