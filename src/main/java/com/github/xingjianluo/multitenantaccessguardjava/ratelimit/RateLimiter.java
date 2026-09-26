package com.github.xingjianluo.multitenantaccessguardjava.ratelimit;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * 登录失败与敏感操作的频率约束与临时锁定。
 * - 计数按固定窗口统计，窗口切换与自增在 ConcurrentHashMap.compute 内原子完成，并发下计数准确；
 * - 失败达到阈值即锁定，锁定期满后惰性自动恢复；
 * - 锁定状态只通过 putIfAbsent/remove(key, value) 等原子操作变更，并发下状态一致。
 */
@Component
public class RateLimiter {

    private static final class Window {
        private final long windowStartSecond;
        private final AtomicInteger count = new AtomicInteger();

        private Window(long windowStartSecond) {
            this.windowStartSecond = windowStartSecond;
        }
    }

    private final ConcurrentHashMap<String, Window> attempts = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<String, Window> failures = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<String, Instant> locks = new ConcurrentHashMap<>();

    private final Clock clock;
    private final long windowSeconds;
    private final int maxAttemptsPerWindow;
    private final int lockThreshold;
    private final Duration lockDuration;

    public RateLimiter(Clock clock,
                       @Value("${guard.ratelimit.window-seconds:60}") long windowSeconds,
                       @Value("${guard.ratelimit.max-attempts-per-window:20}") int maxAttemptsPerWindow,
                       @Value("${guard.ratelimit.lock-threshold:5}") int lockThreshold,
                       @Value("${guard.ratelimit.lock-duration-seconds:60}") long lockDurationSeconds) {
        this.clock = clock;
        this.windowSeconds = windowSeconds;
        this.maxAttemptsPerWindow = maxAttemptsPerWindow;
        this.lockThreshold = lockThreshold;
        this.lockDuration = Duration.ofSeconds(lockDurationSeconds);
    }

    /** 敏感操作前检查：先查锁定，再按窗口计数限流。 */
    public RateLimitResult check(String key) {
        Instant lockedUntil = activeLock(key);
        if (lockedUntil != null) {
            return RateLimitResult.locked(lockedUntil);
        }
        int count = increment(attempts, key);
        if (count > maxAttemptsPerWindow) {
            return RateLimitResult.rateLimited();
        }
        return RateLimitResult.allow();
    }

    /** 记录一次失败，达到阈值则进入临时锁定。 */
    public RateLimitResult recordFailure(String key) {
        Instant lockedUntil = activeLock(key);
        if (lockedUntil != null) {
            return RateLimitResult.locked(lockedUntil);
        }
        int count = increment(failures, key);
        if (count >= lockThreshold) {
            Instant until = clock.instant().plus(lockDuration);
            // 并发下只有一个线程能建立锁；已存在则更保守地取更晚的解锁时间。
            locks.merge(key, until, (a, b) -> a.isAfter(b) ? a : b);
            failures.remove(key);
            return RateLimitResult.locked(locks.get(key));
        }
        return RateLimitResult.allow();
    }

    /** 成功后清零计数。 */
    public void reset(String key) {
        attempts.remove(key);
        failures.remove(key);
    }

    /** 锁定期满自动恢复：过期锁惰性清除。 */
    private Instant activeLock(String key) {
        Instant until = locks.get(key);
        if (until == null) {
            return null;
        }
        if (clock.instant().isBefore(until)) {
            return until;
        }
        locks.remove(key, until);
        return null;
    }

    private int increment(ConcurrentHashMap<String, Window> map, String key) {
        long currentWindow = clock.instant().getEpochSecond() / windowSeconds;
        Window window = map.compute(key, (k, existing) ->
                existing == null || existing.windowStartSecond != currentWindow
                        ? new Window(currentWindow) : existing);
        return window.count.incrementAndGet();
    }
}
