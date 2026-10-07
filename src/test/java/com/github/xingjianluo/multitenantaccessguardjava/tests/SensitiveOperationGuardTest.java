package com.github.xingjianluo.multitenantaccessguardjava.tests;

import com.github.xingjianluo.multitenantaccessguardjava.domain.Action;
import com.github.xingjianluo.multitenantaccessguardjava.ratelimit.SensitiveOperationGuard;
import com.github.xingjianluo.multitenantaccessguardjava.ratelimit.SensitiveOperationGuard.GuardResult;
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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** 业务场景：敏感操作临时锁定（阈值边界、到期恢复、与限流区分、并发一致性）。 */
class SensitiveOperationGuardTest {

    private static final Logger log = LoggerFactory.getLogger(SensitiveOperationGuardTest.class);

    private MutableClock clock;
    private SensitiveOperationGuard guard;

    @BeforeEach
    void setUp() {
        clock = new MutableClock(Instant.parse("2026-10-08T00:00:00Z"));
        // 窗口 60s，每窗口最多 10 次尝试，连续失败 3 次锁定，锁 120s
        guard = new SensitiveOperationGuard(clock, 60, 10, 3, 120);
    }

    @Test
    void lockThresholdBoundaryIsExact() {
        // 阈值边界：第 1、2 次失败不锁定，第 3 次失败进入锁定
        assertFalse(guard.recordFailure("tenant-a", "u1", Action.WRITE).locked());
        assertFalse(guard.recordFailure("tenant-a", "u1", Action.WRITE).locked());
        GuardResult third = guard.recordFailure("tenant-a", "u1", Action.WRITE);
        log.info("TEST-SENSITIVE subject=u1 tenant=tenant-a action=WRITE locked={} until={}",
                third.locked(), third.lockedUntil());
        assertTrue(third.locked(), "第 3 次连续失败必须进入锁定");
        // 锁定期间：前置检查直接拒绝，不会放行
        GuardResult during = guard.check("tenant-a", "u1", Action.WRITE);
        assertTrue(during.locked());
        assertFalse(during.permitted(), "已锁定主体不得被放行");
    }

    @Test
    void lockAutoRecoversAfterExpiry() {
        guard.recordFailure("tenant-a", "u2", Action.DELETE);
        guard.recordFailure("tenant-a", "u2", Action.DELETE);
        assertTrue(guard.recordFailure("tenant-a", "u2", Action.DELETE).locked());

        clock.advance(Duration.ofSeconds(119));
        assertTrue(guard.check("tenant-a", "u2", Action.DELETE).locked(), "锁定未满期不得恢复");

        clock.advance(Duration.ofSeconds(2));
        GuardResult after = guard.check("tenant-a", "u2", Action.DELETE);
        log.info("TEST-SENSITIVE subject=u2 tenant=tenant-a action=DELETE afterExpiry locked={}",
                after.locked());
        assertTrue(after.permitted(), "锁定期满应自动恢复，无需人工解锁");
    }

    @Test
    void lockedIsDistinctFromRateLimited() {
        // 单纯限流：窗口内尝试超限 → permitted=false 但 locked=false
        for (int i = 0; i < 10; i++) {
            assertTrue(guard.check("tenant-a", "u3", Action.WRITE).permitted());
        }
        GuardResult limited = guard.check("tenant-a", "u3", Action.WRITE);
        log.info("TEST-SENSITIVE subject=u3 tenant=tenant-a action=WRITE permitted={} locked={}",
                limited.permitted(), limited.locked());
        assertFalse(limited.permitted());
        assertFalse(limited.locked(), "限流与锁定必须可区分：超限不等于锁定");

        // 另一主体触发锁定 → locked=true，两种拒绝结果不同
        guard.recordFailure("tenant-a", "u4", Action.WRITE);
        guard.recordFailure("tenant-a", "u4", Action.WRITE);
        GuardResult locked = guard.recordFailure("tenant-a", "u4", Action.WRITE);
        assertTrue(locked.locked());
        assertFalse(locked.permitted());
    }

    @Test
    void successResetsConsecutiveFailures() {
        guard.recordFailure("tenant-a", "u5", Action.WRITE);
        guard.recordFailure("tenant-a", "u5", Action.WRITE);
        guard.recordSuccess("tenant-a", "u5", Action.WRITE);
        // 成功后重新计数：再失败 2 次仍不锁定，第 3 次才锁
        assertFalse(guard.recordFailure("tenant-a", "u5", Action.WRITE).locked());
        assertFalse(guard.recordFailure("tenant-a", "u5", Action.WRITE).locked());
        assertTrue(guard.recordFailure("tenant-a", "u5", Action.WRITE).locked());
    }

    @Test
    void keysAreIsolatedPerTenantSubjectAndAction() {
        guard.recordFailure("tenant-a", "u6", Action.WRITE);
        guard.recordFailure("tenant-a", "u6", Action.WRITE);
        assertTrue(guard.recordFailure("tenant-a", "u6", Action.WRITE).locked());
        // 同主体不同动作、不同租户同主体：互不影响
        assertTrue(guard.check("tenant-a", "u6", Action.DELETE).permitted());
        assertTrue(guard.check("tenant-b", "u6", Action.WRITE).permitted());
    }

    @Test
    void concurrentFailuresLockAndNeverPassWhileLocked() throws Exception {
        int threads = 16;
        ExecutorService pool = Executors.newFixedThreadPool(threads);
        CountDownLatch ready = new CountDownLatch(threads);
        CountDownLatch go = new CountDownLatch(1);
        AtomicInteger lockedResponses = new AtomicInteger();
        for (int i = 0; i < threads; i++) {
            pool.submit(() -> {
                ready.countDown();
                try {
                    go.await();
                    if (guard.recordFailure("tenant-a", "u7", Action.WRITE).locked()) {
                        lockedResponses.incrementAndGet();
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
        log.info("TEST-SENSITIVE subject=u7 tenant=tenant-a action=WRITE lockedResponses={}",
                lockedResponses.get());
        assertTrue(lockedResponses.get() >= 1, "并发失败必须触发锁定");

        // 锁定状态下并发前置检查：无一放行
        AtomicInteger permitted = new AtomicInteger();
        ExecutorService pool2 = Executors.newFixedThreadPool(threads);
        CountDownLatch ready2 = new CountDownLatch(threads);
        CountDownLatch go2 = new CountDownLatch(1);
        for (int i = 0; i < threads; i++) {
            pool2.submit(() -> {
                ready2.countDown();
                try {
                    go2.await();
                    if (guard.check("tenant-a", "u7", Action.WRITE).permitted()) {
                        permitted.incrementAndGet();
                    }
                } catch (InterruptedException ignored) {
                    Thread.currentThread().interrupt();
                }
            });
        }
        ready2.await();
        go2.countDown();
        pool2.shutdown();
        pool2.awaitTermination(10, TimeUnit.SECONDS);
        assertEquals(0, permitted.get(), "已锁定主体的并发请求不得有任何放行");
    }
}
