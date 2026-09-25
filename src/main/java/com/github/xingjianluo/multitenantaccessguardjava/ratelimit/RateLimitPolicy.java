package com.github.xingjianluo.multitenantaccessguardjava.ratelimit;

/**
 * A fixed-window failure policy: after {@code maxFailures} failures within
 * {@code windowMillis} the key is locked for {@code lockMillis}. The lock expires
 * automatically (evaluated lazily on the next hit), restoring access.
 */
public record RateLimitPolicy(int maxFailures, long windowMillis, long lockMillis) {
}
