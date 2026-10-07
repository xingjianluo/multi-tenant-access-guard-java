package com.github.xingjianluo.multitenantaccessguardjava.ratelimit;

import com.github.xingjianluo.multitenantaccessguardjava.domain.Action;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.time.Clock;
import java.time.Instant;

/**
 * 敏感操作（写/删）守卫：在限流之外提供基于连续失败的临时锁定。
 * - 计数键为 租户 + 主体 + 动作，不同主体、不同动作的计数互不影响；
 * - 窗口内尝试超限 → RATE_LIMITED（单纯限流）；
 * - 连续失败达到阈值 → LOCKED（明确锁定状态），与限流可区分；
 * - 锁定期满惰性自动恢复，无需人工解锁；成功操作清零失败计数；
 * - 底层复用 RateLimiter 的原子窗口计数与原子锁定，并发下计数与状态一致，
 *   已锁定的主体不会被放行。
 */
@Component
public class SensitiveOperationGuard {

    /** 敏感操作前置/后置判定结果。 */
    public record GuardResult(boolean permitted, boolean locked, Instant lockedUntil) {

        public static GuardResult allow() {
            return new GuardResult(true, false, null);
        }

        public static GuardResult rateLimited() {
            return new GuardResult(false, false, null);
        }

        public static GuardResult locked(Instant until) {
            return new GuardResult(false, true, until);
        }
    }

    private final RateLimiter limiter;

    public SensitiveOperationGuard(Clock clock,
                                   @Value("${guard.sensitive.window-seconds:60}") long windowSeconds,
                                   @Value("${guard.sensitive.max-attempts-per-window:20}") int maxAttempts,
                                   @Value("${guard.sensitive.lock-threshold:5}") int lockThreshold,
                                   @Value("${guard.sensitive.lock-duration-seconds:60}") long lockDurationSeconds) {
        this.limiter = new RateLimiter(clock, windowSeconds, maxAttempts,
                lockThreshold, lockDurationSeconds);
    }

    /** 敏感操作前检查：已锁定 → LOCKED；窗口超限 → RATE_LIMITED；否则放行。 */
    public GuardResult check(String tenantId, String userId, Action action) {
        return adapt(limiter.check(key(tenantId, userId, action)));
    }

    /** 敏感操作被拒绝后记录失败：达到阈值进入锁定并返回 LOCKED。 */
    public GuardResult recordFailure(String tenantId, String userId, Action action) {
        return adapt(limiter.recordFailure(key(tenantId, userId, action)));
    }

    /** 敏感操作成功后清零计数。 */
    public void recordSuccess(String tenantId, String userId, Action action) {
        limiter.reset(key(tenantId, userId, action));
    }

    private static GuardResult adapt(RateLimitResult result) {
        if (result.locked()) {
            return GuardResult.locked(result.lockedUntil());
        }
        return result.permitted() ? GuardResult.allow() : GuardResult.rateLimited();
    }

    private static String key(String tenantId, String userId, Action action) {
        return "sensitive:" + tenantId + ":" + userId + ":" + action;
    }
}
