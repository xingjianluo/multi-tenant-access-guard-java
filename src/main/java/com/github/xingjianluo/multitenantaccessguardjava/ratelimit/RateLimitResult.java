package com.github.xingjianluo.multitenantaccessguardjava.ratelimit;

import java.time.Instant;

/** 限流/锁定判定结果。 */
public record RateLimitResult(boolean permitted, boolean locked, Instant lockedUntil) {

    public static RateLimitResult allow() {
        return new RateLimitResult(true, false, null);
    }

    public static RateLimitResult rateLimited() {
        return new RateLimitResult(false, false, null);
    }

    public static RateLimitResult locked(Instant until) {
        return new RateLimitResult(false, true, until);
    }
}
