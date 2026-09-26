package com.github.xingjianluo.multitenantaccessguardjava.tests;

import com.github.xingjianluo.multitenantaccessguardjava.auth.InMemoryRefreshStore;
import com.github.xingjianluo.multitenantaccessguardjava.auth.RefreshRecord;
import com.github.xingjianluo.multitenantaccessguardjava.auth.RefreshStore;
import com.github.xingjianluo.multitenantaccessguardjava.auth.RefreshVerdict;
import com.github.xingjianluo.multitenantaccessguardjava.model.DenyReason;
import com.github.xingjianluo.multitenantaccessguardjava.model.LoginEntry;
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
import static org.junit.jupiter.api.Assertions.assertTrue;

class RefreshStoreTest {

    private static final Logger log = LoggerFactory.getLogger(RefreshStoreTest.class);

    @Test
    @DisplayName("首次续期成功，旧令牌重放被拒并吊销整个家族")
    void rotateThenReplayRevokesFamily() {
        RefreshStore store = new InMemoryRefreshStore();
        store.save(new RefreshRecord("fam", "rt-1", "tenant-a", "alice",
                LoginEntry.PASSWORD, 10_000L, false, false));

        RefreshVerdict first = store.consume("rt-1", "rt-2", 20_000L, 100L);
        assertEquals(RefreshVerdict.Status.OK, first.status());

        // replaying the consumed token is detected and revokes the family
        RefreshVerdict replay = store.consume("rt-1", "rt-x", 20_000L, 101L);
        assertEquals(RefreshVerdict.Status.REPLAY, replay.status());
        assertEquals(DenyReason.CREDENTIAL_REPLAYED, replay.denyReason());

        // even the freshly minted token now fails because the family is revoked
        RefreshVerdict after = store.consume("rt-2", "rt-3", 30_000L, 102L);
        assertEquals(RefreshVerdict.Status.REVOKED, after.status());
        assertEquals(DenyReason.CREDENTIAL_REVOKED, after.denyReason());

        assertTrue(store.findByFamily("fam").revoked());
        log.info("TEST|case=rotateThenReplayRevokesFamily|tenant=tenant-a|subject=alice|resource=-|action=REFRESH|basis=first OK then replay revoked family");
    }

    @Test
    @DisplayName("并发续期同一刷新令牌：恰有一次成功，其余全部被拒且不发生重复放行")
    void concurrentRenewalExactlyOneWins() throws Exception {
        RefreshStore store = new InMemoryRefreshStore();
        store.save(new RefreshRecord("fam", "rt-1", "tenant-a", "alice",
                LoginEntry.SSO, 100_000L, false, false));

        int threads = 32;
        ExecutorService pool = Executors.newFixedThreadPool(threads);
        CountDownLatch start = new CountDownLatch(1);
        AtomicInteger ok = new AtomicInteger();
        AtomicInteger rejected = new AtomicInteger();

        for (int i = 0; i < threads; i++) {
            pool.submit(() -> {
                try {
                    start.await();
                    RefreshVerdict v = store.consume("rt-1", "rt-new-" + Thread.currentThread().getId(),
                            200_000L, 100L);
                    if (v.status() == RefreshVerdict.Status.OK) {
                        ok.incrementAndGet();
                    } else {
                        rejected.incrementAndGet();
                    }
                } catch (InterruptedException ignored) {
                    Thread.currentThread().interrupt();
                }
            });
        }
        start.countDown();
        pool.shutdown();
        assertTrue(pool.awaitTermination(10, TimeUnit.SECONDS));

        assertEquals(1, ok.get(), "concurrent renewal must release exactly one new token");
        assertEquals(threads - 1, rejected.get());
        assertTrue(store.findByFamily("fam").revoked(), "replay during concurrent renewal revokes the family");
        log.info("TEST|case=concurrentRenewal|tenant=tenant-a|subject=alice|resource=-|action=REFRESH|basis=threads={} ok={} rejected={} revoked={}",
                threads, ok.get(), rejected.get(), store.findByFamily("fam").revoked());
    }

    @Test
    @DisplayName("未知令牌 -> INVALID_CREDENTIAL")
    void unknownToken() {
        RefreshVerdict v = new InMemoryRefreshStore().consume("nope", "rt-2", 1L, 1L);
        assertEquals(RefreshVerdict.Status.UNKNOWN, v.status());
        assertEquals(DenyReason.INVALID_CREDENTIAL, v.denyReason());
        log.info("TEST|case=unknownToken|tenant=-|subject=-|resource=-|action=REFRESH|basis={}", v.denyReason());
    }
}
