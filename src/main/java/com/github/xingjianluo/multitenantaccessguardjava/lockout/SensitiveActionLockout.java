package com.github.xingjianluo.multitenantaccessguardjava.lockout;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.concurrent.ConcurrentHashMap;

/**
 * 敏感操作的临时锁定：同一主体对敏感动作在固定窗口内连续失败达到阈值后，
 * 进入明确的锁定状态，与普通限流相互独立、拒绝原因不同。
 *
 * 并发正确性：
 * - 每个主体映射到一把分段锁（striped lock），控制器在同一把锁内完成
 *   “查锁定 → 限流计数 → 权限判定 → 记失败”整段敏感操作流程，
 *   因此不会出现“已锁定却被放行”，也不会出现失败计数丢失；
 * - 失败计数的窗口滚动、自增与锁定建立均在锁内完成；
 * - 锁定期满后惰性自动恢复，无需人工解锁。
 */
@Component
public class SensitiveActionLockout {

    /** 失败计数窗口：窗口起点 + 次数。 */
    private static final class FailureWindow {
        private final long windowStartSecond;
        private int count;

        private FailureWindow(long windowStartSecond) {
            this.windowStartSecond = windowStartSecond;
        }
    }

    private static final int STRIPE_COUNT = 256;

    private final ConcurrentHashMap<String, FailureWindow> failures = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<String, Instant> locks = new ConcurrentHashMap<>();
    private final Object[] stripes;

    private final Clock clock;
    private final int threshold;
    private final Duration lockDuration;
    private final long windowSeconds;

    public SensitiveActionLockout(Clock clock,
                                  @Value("${guard.sensitive-lock.failure-threshold:3}") int threshold,
                                  @Value("${guard.sensitive-lock.lock-duration-seconds:300}") long lockDurationSeconds,
                                  @Value("${guard.sensitive-lock.failure-window-seconds:300}") long windowSeconds) {
        this.clock = clock;
        this.threshold = threshold;
        this.lockDuration = Duration.ofSeconds(lockDurationSeconds);
        this.windowSeconds = windowSeconds;
        Object[] created = new Object[STRIPE_COUNT];
        for (int i = 0; i < STRIPE_COUNT; i++) {
            created[i] = new Object();
        }
        this.stripes = created;
    }

    /** 取主体对应的分段锁：同一主体始终串行化，不同主体大概率并行。 */
    public Object lockFor(String key) {
        return stripes[(key.hashCode() & 0x7fffffff) % STRIPE_COUNT];
    }

    /**
     * 敏感操作前的锁定检查（调用方须持有 {@link #lockFor(String)} 对应的锁）。
     * 锁定期满在此刻惰性清除，之后的请求自动恢复。
     */
    public LockoutResult checkLocked(String key) {
        Instant until = locks.get(key);
        if (until == null) {
            return LockoutResult.notLocked();
        }
        if (clock.instant().isBefore(until)) {
            return LockoutResult.locked(until);
        }
        locks.remove(key, until);
        failures.remove(key);
        return LockoutResult.notLocked();
    }

    /**
     * 记录一次敏感操作失败；连续失败达到阈值即建立锁定。
     * 必须在 {@link #lockFor(String)} 锁内调用，与 {@link #checkLocked(String)} 串行，
     * 保证阈值边界处的请求要么在锁定前完成、要么被锁挡住，不存在漏放。
     */
    public LockoutResult recordFailure(String key) {
        Instant now = clock.instant();
        long currentWindow = now.getEpochSecond() / windowSeconds;
        FailureWindow window = failures.compute(key, (k, existing) -> {
            if (existing == null || existing.windowStartSecond != currentWindow) {
                return new FailureWindow(currentWindow);
            }
            return existing;
        });
        window.count++;
        if (window.count >= threshold) {
            Instant until = now.plus(lockDuration);
            locks.put(key, until);
            failures.remove(key);
            return LockoutResult.locked(until);
        }
        return LockoutResult.notLocked();
    }

    /** 敏感操作成功后清零失败计数（不影响其他主体）。 */
    public void reset(String key) {
        failures.remove(key);
    }
}
