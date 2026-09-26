package com.github.xingjianluo.multitenantaccessguardjava.tests;

import com.github.xingjianluo.multitenantaccessguardjava.audit.AuditService;
import com.github.xingjianluo.multitenantaccessguardjava.audit.LoggingAuditService;
import com.github.xingjianluo.multitenantaccessguardjava.ratelimit.FixedWindowRateLimitService;
import com.github.xingjianluo.multitenantaccessguardjava.ratelimit.RateLimitPolicy;
import com.github.xingjianluo.multitenantaccessguardjava.ratelimit.RateResult;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class RateLimitServiceTest {

    private static final Logger log = LoggerFactory.getLogger(RateLimitServiceTest.class);

    private FixedWindowRateLimitService service;
    private MutableClock clock;
    private AuditService auditService;

    @BeforeEach
    void setUp() {
        clock = MutableClock.startAt(1_000L);
        auditService = new LoggingAuditService();
        service = new FixedWindowRateLimitService(clock, auditService);
        // max 3 failures per 60s window -> 120s lock
        service.registerPolicy("login", new RateLimitPolicy(3, 60_000L, 120_000L));
    }

    @Test
    @DisplayName("达到阈值前放行，第3次失败触发锁定，锁定期内全部拒绝")
    void locksAtThreshold() {
        String key = "login:tenant-a:alice";
        assertTrue(service.penalize(key, clock.nowMillis()).allowed());
        assertTrue(service.penalize(key, clock.nowMillis()).allowed());
        RateResult third = service.penalize(key, clock.nowMillis());
        assertFalse(third.allowed());
        assertEquals(120_000L, third.retryAfterMillis());

        // while locked, even plain checks are blocked
        clock.advance(60_000L);
        assertFalse(service.check(key, clock.nowMillis()).allowed());

        log.info("TEST|case=locksAtThreshold|tenant=tenant-a|subject=alice|resource=-|action=LOGIN|basis=failures=3 lockRetry=60000ms remaining");
    }

    @Test
    @DisplayName("锁定期满自动恢复，计数清零")
    void autoRecoversAfterLock() {
        String key = "login:tenant-a:bob";
        service.penalize(key, clock.nowMillis());
        service.penalize(key, clock.nowMillis());
        service.penalize(key, clock.nowMillis());
        assertFalse(service.check(key, clock.nowMillis()).allowed());

        clock.advance(120_001L);
        RateResult recovered = service.check(key, clock.nowMillis());
        assertTrue(recovered.allowed());
        assertEquals(0, recovered.failures());
        // a fresh failure starts counting from 1 again
        assertEquals(1, service.penalize(key, clock.nowMillis()).failures());
        log.info("TEST|case=autoRecoversAfterLock|tenant=tenant-a|subject=bob|resource=-|action=LOGIN|basis=lock elapsed, counter reset");
    }

    @Test
    @DisplayName("窗口滑动：窗口外的失败不计入锁定")
    void windowResetsFailures() {
        String key = "login:tenant-a:carol";
        service.penalize(key, clock.nowMillis());
        service.penalize(key, clock.nowMillis());
        clock.advance(60_001L); // past the window
        RateResult third = service.penalize(key, clock.nowMillis());
        assertTrue(third.allowed(), "old failures must have aged out of the window");
        assertEquals(1, third.failures());
        log.info("TEST|case=windowResetsFailures|tenant=tenant-a|subject=carol|resource=-|action=LOGIN|basis=window rolled, failures={}", third.failures());
    }

    @Test
    @DisplayName("并发失败计数准确：100个并发penalize恰好锁定一次且计数=100")
    void concurrentCountingIsAccurate() throws Exception {
        String key = "login:tenant-a:dave";
        int threads = 100;
        ExecutorService pool = Executors.newFixedThreadPool(16);
        CountDownLatch start = new CountDownLatch(1);
        AtomicInteger blocked = new AtomicInteger();

        for (int i = 0; i < threads; i++) {
            pool.submit(() -> {
                try {
                    start.await();
                    if (!service.penalize(key, clock.nowMillis()).allowed()) {
                        blocked.incrementAndGet();
                    }
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                }
            });
        }
        start.countDown();
        pool.shutdown();
        assertTrue(pool.awaitTermination(10, TimeUnit.SECONDS));

        RateResult state = service.check(key, clock.nowMillis());
        assertFalse(state.allowed(), "key must be locked after concurrent failures");
        // first maxFailures-1 allowed, the remaining blocked
        assertEquals(threads - 2, blocked.get(), "exactly the post-threshold calls are blocked");
        assertEquals(threads, state.failures());
        log.info("TEST|case=concurrentCounting|tenant=tenant-a|subject=dave|resource=-|action=LOGIN|basis=threads=100 failures={} blocked={}",
                state.failures(), blocked.get());
    }
}
