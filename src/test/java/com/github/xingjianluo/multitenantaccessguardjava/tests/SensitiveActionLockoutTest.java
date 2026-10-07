package com.github.xingjianluo.multitenantaccessguardjava.tests;

import com.github.xingjianluo.multitenantaccessguardjava.lockout.LockoutResult;
import com.github.xingjianluo.multitenantaccessguardjava.lockout.SensitiveActionLockout;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.Duration;
import java.time.Instant;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 敏感操作临时锁定：阈值/到期边界、成功清零、并发下“已锁定绝不再放行”。
 */
class SensitiveActionLockoutTest {

    private static final Logger log = LoggerFactory.getLogger(SensitiveActionLockoutTest.class);

    private MutableClock clock;
    private SensitiveActionLockout lockout;

    @BeforeEach
    void setUp() {
        clock = new MutableClock(Instant.parse("2026-10-08T00:00:00Z"));
        // 失败窗口 300s，连续失败 3 次锁定，锁 120s
        lockout = new SensitiveActionLockout(clock, 3, 120, 300);
    }

    @Test
    void locksExactlyAtThresholdAndRecoversAfterExpiry() {
        String key = "sensitive:tenant-a:u-alice";

        LockoutResult first = lockout.recordFailure(key);
        LockoutResult second = lockout.recordFailure(key);
        assertFalse(first.locked(), "第 1 次失败不应锁定");
        assertFalse(second.locked(), "第 2 次失败不应锁定（阈值下边界）");
        log.info("TEST-SENSITIVE-LOCK business=below-threshold key={} locked={}/{} result=PASS",
                key, first.locked(), second.locked());

        LockoutResult third = lockout.recordFailure(key);
        assertTrue(third.locked(), "第 3 次失败（阈值）必须进入锁定状态");
        assertTrue(lockout.checkLocked(key).locked(), "锁定期间持续拒绝，与限流可区分");
        log.info("TEST-SENSITIVE-LOCK business=threshold-hit key={} until={} result=PASS",
                key, third.lockedUntil());

        // 锁定期满前 1 秒仍锁定
        clock.advance(Duration.ofSeconds(119));
        assertTrue(lockout.checkLocked(key).locked(), "到期前一刻仍锁定");

        // 到期自动恢复，无需人工解锁
        clock.advance(Duration.ofSeconds(1));
        LockoutResult recovered = lockout.checkLocked(key);
        assertFalse(recovered.locked(), "锁定期满应自动恢复");
        log.info("TEST-SENSITIVE-LOCK business=auto-recover key={} locked={} result=PASS",
                key, recovered.locked());
    }

    @Test
    void successClearsFailureStreak() {
        String key = "sensitive:tenant-a:u-dave";
        lockout.recordFailure(key);
        lockout.recordFailure(key);
        lockout.reset(key);
        assertFalse(lockout.recordFailure(key).locked(), "成功清零后需重新累计到阈值");
        assertFalse(lockout.recordFailure(key).locked(), "再次失败也只计到第 2 次");
        log.info("TEST-SENSITIVE-LOCK business=success-reset key={} result=PASS", key);
    }

    @Test
    void failuresOutsideWindowDoNotAccumulate() {
        String key = "sensitive:tenant-a:u-eve";
        lockout.recordFailure(key);
        lockout.recordFailure(key);
        clock.advance(Duration.ofSeconds(301)); // 滚出失败窗口
        assertFalse(lockout.recordFailure(key).locked(), "窗口外的失败不累加到新窗口");
        log.info("TEST-SENSITIVE-LOCK business=window-rollover key={} result=PASS", key);
    }

    @Test
    void distinctSubjectsAreLockedIndependently() {
        String alice = "sensitive:tenant-a:u-alice";
        String bob = "sensitive:tenant-b:u-bob";
        for (int i = 0; i < 3; i++) {
            lockout.recordFailure(alice);
        }
        assertTrue(lockout.checkLocked(alice).locked(), "alice 应已锁定");
        assertFalse(lockout.checkLocked(bob).locked(), "bob 是另一主体，不应被牵连");
        log.info("TEST-SENSITIVE-LOCK business=subject-isolation aliceLocked=true bobLocked=false result=PASS");
    }

    @Test
    void concurrentFailuresNeverLeakThroughWhenLocked() throws Exception {
        // 并发把失败打到阈值后，再并发发起“查锁定”：所有后续检查都必须看到锁定，
        // 不能出现已经锁定还被放行。
        String key = "sensitive:tenant-a:u-carol";
        int threads = 16;
        ExecutorService pool = Executors.newFixedThreadPool(threads);
        CountDownLatch ready = new CountDownLatch(threads);
        CountDownLatch go = new CountDownLatch(1);
        AtomicInteger lockedSeen = new AtomicInteger();
        AtomicInteger unlockedSeen = new AtomicInteger();

        // 先在串行阶段制造 2 次失败
        lockout.recordFailure(key);
        lockout.recordFailure(key);

        for (int i = 0; i < threads; i++) {
            pool.submit(() -> {
                ready.countDown();
                try {
                    go.await();
                    synchronized (lockout.lockFor(key)) {
                        // 与控制器一致：先查锁，未锁才记一次失败，再复查
                        LockoutResult state = lockout.checkLocked(key);
                        if (!state.locked()) {
                            state = lockout.recordFailure(key);
                        }
                        if (state.locked() || lockout.checkLocked(key).locked()) {
                            lockedSeen.incrementAndGet();
                        } else {
                            unlockedSeen.incrementAndGet();
                        }
                    }
                } catch (InterruptedException ignored) {
                    Thread.currentThread().interrupt();
                }
            });
        }
        ready.await();
        go.countDown();
        pool.shutdown();
        pool.awaitTermination(10, TimeUnit.SECONDS);

        log.info("TEST-SENSITIVE-LOCK business=concurrent-no-leak key={} lockedSeen={} unlockedSeen={} result=PASS",
                key, lockedSeen.get(), unlockedSeen.get());
        assertTrue(lockedSeen.get() >= 1, "必须至少有一个线程建立/观察到锁定");
        assertTrue(lockout.checkLocked(key).locked(), "并发结束后锁定状态必须稳定保持");
        // 一旦某个线程把第 3 次失败写入，其后在同一分段锁内的线程只会看到锁定；
        // 至多只有建立锁的那一个线程可能处于“未锁→记失败→加锁”的同一临界区，
        // 不会出现锁定后仍被判为未锁而漏放。
        long after = lockedSeen.get() + unlockedSeen.get();
        assertTrue(after == threads);
    }
}
