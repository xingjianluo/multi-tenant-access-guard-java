package com.github.xingjianluo.multitenantaccessguardjava.ratelimit;

/**
 * Result of a rate-limit check.
 *
 * @param allowed     false while locked
 * @param failures    failures counted in the current window
 * @param retryAfterMillis remaining lock time when blocked (0 otherwise)
 */
public record RateResult(boolean allowed, int failures, long retryAfterMillis) {
}
