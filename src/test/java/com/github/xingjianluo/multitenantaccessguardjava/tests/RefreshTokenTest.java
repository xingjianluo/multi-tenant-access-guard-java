package com.github.xingjianluo.multitenantaccessguardjava.tests;

import com.github.xingjianluo.multitenantaccessguardjava.auth.AuthToken;
import com.github.xingjianluo.multitenantaccessguardjava.auth.CredentialException;
import com.github.xingjianluo.multitenantaccessguardjava.auth.TokenService;
import com.github.xingjianluo.multitenantaccessguardjava.auth.UserDirectory;
import com.github.xingjianluo.multitenantaccessguardjava.domain.DenyReason;
import com.github.xingjianluo.multitenantaccessguardjava.domain.Role;
import com.github.xingjianluo.multitenantaccessguardjava.domain.Subject;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.Instant;
import java.util.Set;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** 业务场景：续期入口收紧（凭据类型隔离、重放整链作废、并发续期、身份绑定）。 */
class RefreshTokenTest {

    private static final Logger log = LoggerFactory.getLogger(RefreshTokenTest.class);

    private MutableClock clock;
    private UserDirectory directory;
    private TokenService tokens;

    @BeforeEach
    void setUp() {
        clock = new MutableClock(Instant.parse("2026-10-08T00:00:00Z"));
        directory = new UserDirectory();
        directory.register("alice", "pw", new Subject("u-alice", "tenant-a", Set.of(Role.USER)));
        directory.register("bob", "pw", new Subject("u-bob", "tenant-b", Set.of(Role.USER)));
        tokens = new TokenService(directory, clock, 60, 600, "test-secret");
    }

    private CredentialException expectDenied(Runnable r) {
        return assertThrows(CredentialException.class, r::run);
    }

    @Test
    void accessTokenCannotBeUsedForRefresh() {
        TokenService.TokenPair pair = tokens.issuePair("u-alice", "tenant-a");
        // 平时访问用的凭据不能拿来续期
        CredentialException e = expectDenied(() -> tokens.refresh(pair.access().serialized()));
        log.info("TEST-REFRESH2 subject=u-alice tenant=tenant-a scenario=accessForRefresh reason={}",
                e.reason());
        assertEquals(DenyReason.CREDENTIAL_TYPE_MISMATCH, e.reason());
    }

    @Test
    void refreshTokenCannotBeUsedForAccess() {
        TokenService.TokenPair pair = tokens.issuePair("u-alice", "tenant-a");
        // 续期凭据不能反过来用于日常访问
        CredentialException e = expectDenied(() -> tokens.authenticate(pair.refresh().serialized()));
        log.info("TEST-REFRESH2 subject=u-alice tenant=tenant-a scenario=refreshForAccess reason={}",
                e.reason());
        assertEquals(DenyReason.CREDENTIAL_TYPE_MISMATCH, e.reason());
    }

    @Test
    void replayedRefreshTokenRevokesWholeChain() {
        TokenService.TokenPair pair = tokens.issuePair("u-alice", "tenant-a");
        TokenService.TokenPair rotated = tokens.refresh(pair.refresh().serialized());
        // 链上续期可继续：新续期凭据可用
        TokenService.TokenPair rotated2 = tokens.refresh(rotated.refresh().serialized());
        assertEquals("u-alice",
                tokens.authenticate(rotated2.access().serialized()).subject().userId());

        // 已轮换过的旧续期凭据再次提交 → 重放，整条链作废
        CredentialException e = expectDenied(() -> tokens.refresh(pair.refresh().serialized()));
        log.info("TEST-REFRESH2 subject=u-alice tenant=tenant-a scenario=replay reason={}",
                e.reason());
        assertEquals(DenyReason.CREDENTIAL_REPLAYED, e.reason());

        // 链上其他凭据一并作废：最新的访问/续期凭据都被拒
        assertEquals(DenyReason.CREDENTIAL_REPLAYED,
                expectDenied(() -> tokens.authenticate(rotated2.access().serialized())).reason());
        assertEquals(DenyReason.CREDENTIAL_REPLAYED,
                expectDenied(() -> tokens.refresh(rotated2.refresh().serialized())).reason());
    }

    @Test
    void concurrentRefreshOnlyOneSucceedsAndKeepsIdentity() throws Exception {
        AuthToken refreshToken = tokens.issuePair("u-alice", "tenant-a").refresh();
        int threads = 16;
        ExecutorService pool = Executors.newFixedThreadPool(threads);
        CountDownLatch ready = new CountDownLatch(threads);
        CountDownLatch go = new CountDownLatch(1);
        AtomicInteger success = new AtomicInteger();
        AtomicInteger replayed = new AtomicInteger();
        var winner = new java.util.concurrent.atomic.AtomicReference<TokenService.TokenPair>();
        for (int i = 0; i < threads; i++) {
            pool.submit(() -> {
                ready.countDown();
                try {
                    go.await();
                    winner.compareAndSet(null, tokens.refresh(refreshToken.serialized()));
                    success.incrementAndGet();
                } catch (CredentialException e) {
                    if (e.reason() == DenyReason.CREDENTIAL_REPLAYED) {
                        replayed.incrementAndGet();
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
        log.info("TEST-REFRESH2 subject=u-alice tenant=tenant-a scenario=concurrent success={} replayed={}",
                success.get(), replayed.get());
        assertEquals(1, success.get(), "并发续期只能有一份凭据被成功续期");
        assertEquals(threads - 1, replayed.get(), "其余必须判定为重放");

        // 胜出新凭据的身份不漂移：仍是原主体、原租户
        assertEquals("u-alice", winner.get().access().subjectUserId());
        assertEquals("tenant-a", winner.get().access().tenantId());
        // 重放已触发整链作废：胜出新凭据同样被拒，任何一方都无法继续使用该链
        assertEquals(DenyReason.CREDENTIAL_REPLAYED,
                expectDenied(() -> tokens.authenticate(winner.get().access().serialized())).reason());
    }

    @Test
    void refreshKeepsIdentityBoundToOriginalTenantAndSubject() {
        TokenService.TokenPair alicePair = tokens.issuePair("u-alice", "tenant-a");
        TokenService.TokenPair rotated = tokens.refresh(alicePair.refresh().serialized());
        // 续期后的身份仍绑定原主体与原租户，不会认到别的租户或主体上
        var ctx = tokens.authenticate(rotated.access().serialized());
        assertEquals("u-alice", ctx.subject().userId());
        assertEquals("tenant-a", ctx.subject().tenantId());

        // 不同租户的续期链互不影响：bob 的链独立轮换
        TokenService.TokenPair bobPair = tokens.issuePair("u-bob", "tenant-b");
        TokenService.TokenPair bobRotated = tokens.refresh(bobPair.refresh().serialized());
        assertEquals("u-bob", tokens.authenticate(bobRotated.access().serialized()).subject().userId());
        assertEquals("tenant-b",
                tokens.authenticate(bobRotated.access().serialized()).subject().tenantId());
        // alice 的重放不会误伤 bob 的链
        expectDenied(() -> tokens.refresh(alicePair.refresh().serialized()));
        assertTrue(tokens.authenticate(bobRotated.access().serialized()).subject().userId()
                .equals("u-bob"));
    }
}
