package com.github.xingjianluo.multitenantaccessguardjava.ratelimit;

/**
 * Frequency control and temporary lockout for failed logins and sensitive actions.
 * All counters and lock transitions are synchronized per key so that concurrent
 * requests count accurately; locks self-expire.
 */
public interface RateLimitService {

    /** Gate a request. Returns blocked while the key is locked; otherwise allowed. */
    RateResult check(String key, long nowMillis);

    /**
     * Register one failure against the key. When the failure count reaches the policy
     * threshold the key becomes locked. Returns the post-update state.
     */
    RateResult penalize(String key, long nowMillis);

    /** Clear failures/lock for a key (e.g. successful login). */
    void reset(String key);
}
