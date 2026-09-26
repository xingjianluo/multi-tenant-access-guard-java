package com.github.xingjianluo.multitenantaccessguardjava.ratelimit;

import com.github.xingjianluo.multitenantaccessguardjava.audit.AuditEvent;
import com.github.xingjianluo.multitenantaccessguardjava.audit.AuditService;
import com.github.xingjianluo.multitenantaccessguardjava.support.TimeSource;
import org.springframework.stereotype.Service;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Fixed-window failure counter with temporary lockout.
 *
 * <p>State per key: window start, failure count, lock-until. All transitions for a key
 * are synchronized on that key's state object, so concurrent failures count exactly
 * once each and the lock decision is atomic. Lock expiry is evaluated lazily: a check
 * after {@code lockUntil} clears the lock and starts a fresh window, i.e. access
 * recovers automatically.
 */
@Service
public class FixedWindowRateLimitService implements RateLimitService {

    private static final class State {
        long windowStart;
        int failures;
        long lockedUntil;
    }

    private final TimeSource timeSource;
    private final AuditService auditService;
    private final Map<String, State> states = new ConcurrentHashMap<>();

    public FixedWindowRateLimitService(TimeSource timeSource, AuditService auditService) {
        this.timeSource = timeSource;
        this.auditService = auditService;
    }

    @Override
    public RateResult check(String key, long nowMillis) {
        State st = states.get(key);
        if (st == null) {
            return new RateResult(true, 0, 0L);
        }
        synchronized (st) {
            if (st.lockedUntil > nowMillis) {
                return new RateResult(false, st.failures, st.lockedUntil - nowMillis);
            }
            if (st.lockedUntil != 0L && st.lockedUntil <= nowMillis) {
                // lock just expired: start a clean window
                st.lockedUntil = 0L;
                st.windowStart = nowMillis;
                st.failures = 0;
            }
            return new RateResult(true, st.failures, 0L);
        }
    }

    @Override
    public RateResult penalize(String key, long nowMillis) {
        State st = states.computeIfAbsent(key, k -> new State());
        synchronized (st) {
            // Auto-expire an elapsed lock before counting new failures.
            if (st.lockedUntil != 0L && st.lockedUntil <= nowMillis) {
                st.lockedUntil = 0L;
                st.windowStart = nowMillis;
                st.failures = 0;
            }
            if (nowMillis - st.windowStart > currentWindow(key)) {
                st.windowStart = nowMillis;
                st.failures = 0;
            }
            if (st.windowStart == 0L) {
                st.windowStart = nowMillis;
            }
            st.failures++;
            RateLimitPolicy policy = policyFor(key);
            if (st.failures >= policy.maxFailures() && st.lockedUntil <= nowMillis) {
                st.lockedUntil = nowMillis + policy.lockMillis();
                audit(key, st, policy, nowMillis);
                return new RateResult(false, st.failures, policy.lockMillis());
            }
            if (st.lockedUntil > nowMillis) {
                return new RateResult(false, st.failures, st.lockedUntil - nowMillis);
            }
            return new RateResult(true, st.failures, 0L);
        }
    }

    @Override
    public void reset(String key) {
        states.remove(key);
    }

    /** Policy lookup point; the key family prefix selects login vs sensitive policy. */
    private RateLimitPolicy policyFor(String key) {
        int colon = key.indexOf(':');
        String family = colon > 0 ? key.substring(0, colon) : key;
        RateLimitPolicy policy = policies.get(family);
        if (policy == null) {
            throw new IllegalStateException("no rate-limit policy registered for family " + family);
        }
        return policy;
    }

    private long currentWindow(String key) {
        return policyFor(key).windowMillis();
    }

    private final Map<String, RateLimitPolicy> policies = new ConcurrentHashMap<>();

    /** Register the policy that applies to a key family prefix (called at wiring time). */
    public void registerPolicy(String family, RateLimitPolicy policy) {
        policies.put(family, policy);
    }

    private void audit(String key, State st, RateLimitPolicy policy, long nowMillis) {
        String[] parts = key.split(":", 3);
        String tenant = parts.length > 1 ? parts[1] : null;
        String subject = parts.length > 2 ? parts[2] : key;
        auditService.record(new AuditEvent(nowMillis, "RATE_LIMIT_LOCKED", tenant, subject,
                null, null, null, false, "LOCKED",
                "failures=" + st.failures + " lockMillis=" + policy.lockMillis() + " key=" + key,
                null, null));
    }
}
