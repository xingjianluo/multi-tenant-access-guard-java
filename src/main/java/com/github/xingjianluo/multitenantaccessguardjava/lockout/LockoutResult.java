package com.github.xingjianluo.multitenantaccessguardjava.lockout;

import java.time.Instant;

/** 敏感操作锁定判定结果。 */
public record LockoutResult(boolean locked, Instant lockedUntil) {

    public static LockoutResult notLocked() {
        return new LockoutResult(false, null);
    }

    public static LockoutResult locked(Instant until) {
        return new LockoutResult(true, until);
    }
}
