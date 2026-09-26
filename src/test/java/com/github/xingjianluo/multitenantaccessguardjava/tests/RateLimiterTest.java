package com.github.xingjianluo.multitenantaccessguardjava.tests;

import com.github.xingjianluo.multitenantaccessguardjava.ratelimit.RateLimitResult;
import com.github.xingjianluo.multitenantaccessguardjava.ratelimit.RateLimiter;
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

class RateLimiterTest {

    private static final Logger log = LoggerFactory.getLogger(RateLimiterTest.class);

    private MutableClock clock;
    private RateLimiter limiter;

    @BeforeEach
    void setUp() {
        clock = new MutableClock(Instant.parse("2026-09-26T00:00:00Z"));
        // 窗口 60s，每窗口最多 10 次尝试，失败 5 次锁定，锁 60s
        limiter = new RateLimiter(clock, 60, 10, 5, 60);
    }

    @Test
    void locksAfterThresholdAndAutoRecovers() {
        String key = "login:alice";
        for (int i = 0; i < 4; i++) {
            assertFalse(limiter.recordFailure(key).locked(), "第 " + (i + 1) + " 次失败不应锁定");
        }
        RateLimitResult fifth = limiter.recordFailure(key);
        log.info("TEST-LOCK subject=alice locked={} until={}", fifth.locked(), fifth.lockedUntil());
        assertTrue(fifth.locked(), "第 5 次失败应触发锁定");
        assertTrue(limiter.check(key).locked(), "锁定期间检查应返回锁定");

        clock.advance(Duration.ofSeconds(61));
        RateLimitResult after = limiter.check(key);
        log.info("TEST-LOCK subject=alice afterExpiry locked={}", after.locked());
        assertTrue(after.permitted(), "锁定期满应自动恢复");
    }

    @Test
    void rateLimitBoundaryIsExact() {
        String key = "sensitive:u1";
        for (int i = 0; i < 10; i++) {
            assertTrue(limiter.check(key).permitted(), "第 " + (i + 1) + " 次应放行");
        }
        assertFalse(limiter.check(key).permitted(), "第 11 次应被限流");
        // 窗口滚动后恢复
        clock.advance(Duration.ofSeconds(61));
        assertTrue(limiter.check(key).permitted(), "新窗口应恢复");
    }

    @Test
    void concurrentCountingIsAccurate() throws Exception {
        String key = "sensitive:u2";
        int threads = 8, perThread = 10, total = threads * perThread;
        ExecutorService pool = Executors.newFixedThreadPool(threads);
        CountDownLatch ready = new CountDownLatch(threads);
        CountDownLatch go = new CountDownLatch(1);
        AtomicInteger permitted = new AtomicInteger();
        for (int i = 0; i < threads; i++) {
            pool.submit(() -> {
                ready.countDown();
                try {
                    go.await();
                    for (int j = 0; j < perThread; j++) {
                        if (limiter.check(key).permitted()) {
                            permitted.incrementAndGet();
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
        log.info("TEST-RATE subject=u2 total={} permitted={}", total, permitted.get());
        assertEquals(10, permitted.get(), "并发下恰好放行窗口上限次数，计数必须准确");
    }

    @Test
    void concurrentFailuresLockExactly() throws Exception {
        String key = "login:bob";
        int threads = 20;
        ExecutorService pool = Executors.newFixedThreadPool(threads);
        CountDownLatch ready = new CountDownLatch(threads);
        CountDownLatch go = new CountDownLatch(1);
        AtomicInteger lockedResponses = new AtomicInteger();
        for (int i = 0; i < threads; i++) {
            pool.submit(() -> {
                ready.countDown();
                try {
                    go.await();
                    if (limiter.recordFailure(key).locked()) {
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
        log.info("TEST-LOCK subject=bob lockedResponses={}", lockedResponses.get());
        assertTrue(lockedResponses.get() >= 1, "并发失败必须触发锁定");
        assertTrue(limiter.check(key).locked(), "锁定状态并发下保持一致");
    }

    @Test
    void successResetsCounters() {
        String key = "login:carol";
        for (int i = 0; i < 4; i++) {
            limiter.recordFailure(key);
        }
        limiter.reset(key);
        for (int i = 0; i < 4; i++) {
            assertFalse(limiter.recordFailure(key).locked());
        }
        assertTrue(limiter.recordFailure(key).locked(), "重置后需重新累计到阈值才锁定");
    }
}
