package com.github.xingjianluo.multitenantaccessguardjava.tests;

import com.github.xingjianluo.multitenantaccessguardjava.auth.AuthToken;
import com.github.xingjianluo.multitenantaccessguardjava.auth.CredentialException;
import com.github.xingjianluo.multitenantaccessguardjava.auth.RenewalResult;
import com.github.xingjianluo.multitenantaccessguardjava.auth.TokenPair;
import com.github.xingjianluo.multitenantaccessguardjava.auth.TokenService;
import com.github.xingjianluo.multitenantaccessguardjava.auth.UserDirectory;
import com.github.xingjianluo.multitenantaccessguardjava.domain.AuthContext;
import com.github.xingjianluo.multitenantaccessguardjava.domain.DenyReason;
import com.github.xingjianluo.multitenantaccessguardjava.domain.Role;
import com.github.xingjianluo.multitenantaccessguardjava.domain.Subject;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.Duration;
import java.time.Instant;
import java.util.Set;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class TokenServiceTest {

    private static final Logger log = LoggerFactory.getLogger(TokenServiceTest.class);

    private MutableClock clock;
    private UserDirectory directory;
    private TokenService tokens;

    @BeforeEach
    void setUp() {
        clock = new MutableClock(Instant.parse("2026-09-26T00:00:00Z"));
        directory = new UserDirectory();
        directory.register("alice", "pw", new Subject("u-alice", "tenant-a", Set.of(Role.USER)));
        directory.register("bob", "pw", new Subject("u-bob", "tenant-b", Set.of(Role.USER)));
        // access TTL 60s，refresh TTL 120s
        tokens = new TokenService(directory, clock, 60, "test-secret");
    }

    private TokenPair pair(String user, String tenant) {
        return tokens.issuePair(user, tenant);
    }

    private static CredentialException expectFailure(org.junit.jupiter.api.function.Executable action) {
        return assertThrows(CredentialException.class, action);
    }

    @Test
    void validAccessTokenAuthenticates() {
        TokenPair p = pair("u-alice", "tenant-a");
        AuthContext ctx = tokens.authenticate(p.accessToken().serialized());
        assertEquals("u-alice", ctx.subject().userId());
        assertEquals("tenant-a", ctx.subject().tenantId());
        log.info("TEST-CREDENTIAL business=access-auth subject=u-alice tenant=tenant-a result=PASS");
    }

    @Test
    void expiredAccessTokenIsRejected() {
        TokenPair p = pair("u-alice", "tenant-a");
        clock.advance(Duration.ofSeconds(61));
        CredentialException e = expectFailure(() -> tokens.authenticate(p.accessToken().serialized()));
        log.info("TEST-CREDENTIAL business=access-expiry subject=u-alice reason={} result=PASS", e.reason());
        assertEquals(DenyReason.CREDENTIAL_EXPIRED, e.reason());
    }

    @Test
    void tamperedTokenIsRejected() {
        TokenPair p = pair("u-alice", "tenant-a");
        int dot = p.accessToken().serialized().lastIndexOf('.');
        String body = p.accessToken().serialized().substring(0, dot);
        char c = body.charAt(5);
        char flipped = c == 'A' ? 'B' : 'A';
        String tampered = body.substring(0, 5) + flipped + body.substring(6)
                + p.accessToken().serialized().substring(dot);
        CredentialException e = expectFailure(() -> tokens.authenticate(tampered));
        log.info("TEST-CREDENTIAL business=tamper subject=u-alice reason={} result=PASS", e.reason());
        assertEquals(DenyReason.CREDENTIAL_TAMPERED, e.reason());
    }

    @Test
    void accessCredentialCannotBeUsedToRefresh() {
        // 续期入口收紧：平时访问用的凭据拿来续 → 明确的 NOT_REFRESHABLE，区别于重放/过期
        TokenPair p = pair("u-alice", "tenant-a");
        CredentialException e = expectFailure(() -> tokens.renew(p.accessToken().serialized()));
        log.info("TEST-REFRESH-SCOPE business=access-at-refresh subject=u-alice reason={} result=PASS", e.reason());
        assertEquals(DenyReason.CREDENTIAL_NOT_REFRESHABLE, e.reason());
    }

    @Test
    void refreshCredentialCannotBeUsedAtResourceEntry() {
        // 续期凭据不能当访问凭据提交到业务入口
        TokenPair p = pair("u-alice", "tenant-a");
        CredentialException e = expectFailure(() -> tokens.authenticate(p.refreshToken().serialized()));
        log.info("TEST-REFRESH-SCOPE business=refresh-at-resource subject=u-alice reason={} result=PASS", e.reason());
        assertEquals(DenyReason.CREDENTIAL_TYPE_MISMATCH, e.reason());
    }

    @Test
    void refreshRotatesAndOldCredentialIsReplay() {
        TokenPair first = pair("u-alice", "tenant-a");
        RenewalResult rotated = tokens.renew(first.refreshToken().serialized());
        assertNotEquals(first.refreshToken().tokenId(), rotated.refreshToken().tokenId());

        // 旧 refresh 再次提交 → 紧邻重放，拒绝
        CredentialException replay = expectFailure(() -> tokens.renew(first.refreshToken().serialized()));
        assertEquals(DenyReason.CREDENTIAL_REPLAYED, replay.reason());
        log.info("TEST-RENEWAL business=immediate-replay subject=u-alice reason={} result=PASS", replay.reason());

        // 新 access 可用，身份仍在原租户/主体
        AuthContext ctx = tokens.authenticate(rotated.accessToken().serialized());
        assertEquals("u-alice", ctx.subject().userId());
        assertEquals("tenant-a", ctx.subject().tenantId());
        log.info("TEST-RENEWAL business=rotate-success subject=u-alice tenant=tenant-a result=PASS");
    }

    @Test
    void staleReplayRevokesWholeChainIncludingAccess() {
        // 连续两次合法续期，得到第一代、第二代 refresh
        TokenPair first = pair("u-bob", "tenant-b");
        RenewalResult r1 = tokens.renew(first.refreshToken().serialized());
        RenewalResult r2 = tokens.renew(r1.refreshToken().serialized());

        // 隔代重放：第一代 refresh 再出现 → 整条链作废
        CredentialException stale = expectFailure(() -> tokens.renew(first.refreshToken().serialized()));
        assertEquals(DenyReason.CREDENTIAL_REPLAYED, stale.reason());
        log.info("TEST-RENEWAL business=stale-replay-revoke subject=u-bob reason={} result=PASS", stale.reason());

        // 链上尚未过期的最新 access 也一起被拒
        CredentialException accessKilled = expectFailure(
                () -> tokens.authenticate(r2.accessToken().serialized()));
        log.info("TEST-RENEWAL business=chain-access-invalidated subject=u-bob reason={} result=PASS",
                accessKilled.reason());
        assertEquals(DenyReason.CREDENTIAL_REPLAYED, accessKilled.reason());

        // 最新一代 refresh 同样被拒，且身份不会错认
        CredentialException refreshKilled = expectFailure(
                () -> tokens.renew(r2.refreshToken().serialized()));
        assertEquals(DenyReason.CREDENTIAL_REPLAYED, refreshKilled.reason());
    }

    @Test
    void differentTenantsChainsDoNotCross() {
        TokenPair a = pair("u-alice", "tenant-a");
        TokenPair b = pair("u-bob", "tenant-b");
        RenewalResult ar = tokens.renew(a.refreshToken().serialized());
        RenewalResult br = tokens.renew(b.refreshToken().serialized());
        assertEquals("tenant-a",
                tokens.authenticate(ar.accessToken().serialized()).subject().tenantId());
        assertEquals("tenant-b",
                tokens.authenticate(br.accessToken().serialized()).subject().tenantId());
        log.info("TEST-RENEWAL business=tenant-identity-isolation result=PASS");
    }

    @Test
    void concurrentRenewOnlyOneSucceeds() throws Exception {
        TokenPair p = pair("u-alice", "tenant-a");
        int threads = 16;
        ExecutorService pool = Executors.newFixedThreadPool(threads);
        CountDownLatch ready = new CountDownLatch(threads);
        CountDownLatch go = new CountDownLatch(1);
        AtomicInteger success = new AtomicInteger();
        AtomicInteger replayed = new AtomicInteger();
        for (int i = 0; i < threads; i++) {
            pool.submit(() -> {
                ready.countDown();
                try {
                    go.await();
                    tokens.renew(p.refreshToken().serialized());
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
        log.info("TEST-RENEWAL business=concurrent-refresh subject=u-alice success={} replayed={} result=PASS",
                success.get(), replayed.get());
        assertEquals(1, success.get(), "并发续期只能有一个成功，一份凭据不能被多次成功续期");
        assertEquals(threads - 1, replayed.get(), "其余必须判定为重放");

        // 落败者提交的旧 refresh 是“紧邻上一代”，只拒绝不作废整条链；
        // 再次提交仍为紧邻重放，且消息可区分，胜出者拿到的新凭据不受影响。
        CredentialException again = expectFailure(() -> tokens.renew(p.refreshToken().serialized()));
        assertEquals(DenyReason.CREDENTIAL_REPLAYED, again.reason());
        assertTrue(again.getMessage().contains("already rotated"));
    }

    @Test
    void roleChangeTakesEffectWithoutReissue() {
        TokenPair p = pair("u-alice", "tenant-a");
        directory.register("alice", "pw", new Subject("u-alice", "tenant-a", Set.of(Role.ADMIN)));
        AuthContext ctx = tokens.authenticate(p.accessToken().serialized());
        assertEquals(Set.of(Role.ADMIN), ctx.subject().roles(), "角色实时加载，旧权限不残留");
        log.info("TEST-CREDENTIAL business=live-role subject=u-alice result=PASS");
    }
}
