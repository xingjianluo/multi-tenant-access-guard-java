package com.github.xingjianluo.multitenantaccessguardjava.tests;

import com.github.xingjianluo.multitenantaccessguardjava.audit.LoggingAuditService;
import com.github.xingjianluo.multitenantaccessguardjava.auth.DefaultAuthenticationService;
import com.github.xingjianluo.multitenantaccessguardjava.auth.DefaultCredentialService;
import com.github.xingjianluo.multitenantaccessguardjava.auth.HmacTokenService;
import com.github.xingjianluo.multitenantaccessguardjava.auth.InMemoryRefreshStore;
import com.github.xingjianluo.multitenantaccessguardjava.auth.TokenBundle;
import com.github.xingjianluo.multitenantaccessguardjava.auth.TokenService;
import com.github.xingjianluo.multitenantaccessguardjava.authz.DefaultAuthorizationService;
import com.github.xingjianluo.multitenantaccessguardjava.authz.InMemoryPermissionStore;
import com.github.xingjianluo.multitenantaccessguardjava.model.Action;
import com.github.xingjianluo.multitenantaccessguardjava.model.Decision;
import com.github.xingjianluo.multitenantaccessguardjava.model.DenyReason;
import com.github.xingjianluo.multitenantaccessguardjava.model.LoginEntry;
import com.github.xingjianluo.multitenantaccessguardjava.model.Permission;
import com.github.xingjianluo.multitenantaccessguardjava.model.Resource;
import com.github.xingjianluo.multitenantaccessguardjava.model.Scope;
import com.github.xingjianluo.multitenantaccessguardjava.model.Subject;
import com.github.xingjianluo.multitenantaccessguardjava.ratelimit.FixedWindowRateLimitService;
import com.github.xingjianluo.multitenantaccessguardjava.ratelimit.RateLimitPolicy;
import com.github.xingjianluo.multitenantaccessguardjava.support.AccessGuardException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.assertThrows;

class AuthenticationServiceTest {

    private static final Logger log = LoggerFactory.getLogger(AuthenticationServiceTest.class);

    private MutableClock clock;
    private DefaultCredentialService creds;
    private DefaultAuthenticationService authn;
    private DefaultAuthorizationService authz;
    private FixedWindowRateLimitService limiter;
    private TokenService tokens;
    private InMemoryPermissionStore permissions;
    private LoggingAuditService audit;

    @BeforeEach
    void setUp() {
        clock = MutableClock.startAt(1_000_000L);
        tokens = new HmacTokenService("test-secret", 1_000L, 3_000L);
        creds = new DefaultCredentialService();
        audit = new LoggingAuditService();
        limiter = new FixedWindowRateLimitService(clock, audit);
        limiter.registerPolicy("login", new RateLimitPolicy(3, 60_000L, 120_000L));
        limiter.registerPolicy("sensitive", new RateLimitPolicy(3, 60_000L, 120_000L));
        authn = new DefaultAuthenticationService(tokens, new InMemoryRefreshStore(), creds,
                limiter, audit, clock);

        permissions = new InMemoryPermissionStore();
        authz = new DefaultAuthorizationService(permissions, creds, audit, clock);
        permissions.addResource(new Resource("tenant-a", "doc-1", "alice"));
        permissions.replacePermissions(List.of(
                new Permission("tenant-a", "alice", "admin", Scope.TENANT, null)));

        creds.registerPasswordAccount("tenant-a", "alice", "alice", "pw", List.of("admin"));
    }

    private void logAuthz(Subject s, String via, Action action, Decision d) {
        log.info("TEST|case=entryConvergence|tenant={}|subject={}|entry={}|resource=doc-1|action={}|allowed={}|basis={}",
                s.tenantId(), s.subjectId(), via, action, d.allowed(), d.basis());
    }

    @Test
    @DisplayName("两种入口解析同一主体，对同一资源的判定结果一致")
    void passwordAndSsoConvergeToSameDecision() {
        TokenBundle pwBundle = authn.login("PASSWORD", "tenant-a", "alice", "pw", null);
        String assertion = creds.issueSsoAssertion("tenant-a", "alice");
        TokenBundle ssoBundle = authn.login("SSO", "tenant-a", null, null, assertion);

        for (Action action : Action.values()) {
            Subject viaPw = authn.authenticate("Bearer " + pwBundle.accessToken().token());
            Subject viaSso = authn.authenticate("Bearer " + ssoBundle.accessToken().token());
            assertEquals(viaPw.tenantId(), viaSso.tenantId());
            assertEquals(viaPw.subjectId(), viaSso.subjectId());
            assertNotEquals(viaPw.loginEntry(), viaSso.loginEntry()); // entries differ ...

            Decision d1 = authz.authorize(viaPw, "tenant-a", "doc-1", action);
            Decision d2 = authz.authorize(viaSso, "tenant-a", "doc-1", action);
            assertEquals(d1.allowed(), d2.allowed());
            assertEquals(d1.reason(), d2.reason());
            logAuthz(viaPw, "PASSWORD", action, d1);
            logAuthz(viaSso, "SSO", action, d2);
        }
    }

    @Test
    @DisplayName("过期访问令牌 -> CREDENTIAL_EXPIRED；篡改令牌 -> INVALID_CREDENTIAL")
    void expiredAndTamperedTokensAreDistinguished() {
        TokenBundle bundle = authn.login("PASSWORD", "tenant-a", "alice", "pw", null);

        clock.advance(1_001L);
        AccessGuardException expired = assertThrows(AccessGuardException.class,
                () -> authn.authenticate("Bearer " + bundle.accessToken().token()));
        assertEquals(DenyReason.CREDENTIAL_EXPIRED, expired.getReason());

        String tampered = "x" + bundle.accessToken().token().substring(1);
        AccessGuardException bad = assertThrows(AccessGuardException.class,
                () -> authn.authenticate("Bearer " + tampered));
        assertEquals(DenyReason.INVALID_CREDENTIAL, bad.getReason());

        AccessGuardException noHeader = assertThrows(AccessGuardException.class,
                () -> authn.authenticate(null));
        assertEquals(DenyReason.UNAUTHENTICATED, noHeader.getReason());
        log.info("TEST|case=tokenFailureReasons|tenant=tenant-a|subject=alice|resource=-|action=AUTHN|basis={}/{}",
                expired.getReason(), bad.getReason());
    }

    @Test
    @DisplayName("SSO断言一次性：重放被拒，原因=CREDENTIAL_REPLAYED，不会二次放行")
    void ssoAssertionIsSingleUse() {
        String assertion = creds.issueSsoAssertion("tenant-a", "alice");
        authn.login("SSO", "tenant-a", null, null, assertion);
        AccessGuardException replay = assertThrows(AccessGuardException.class,
                () -> authn.login("SSO", "tenant-a", null, null, assertion));
        // first replay counts as bad credential event and may lock after repeats; key reason is replay:
        assertEquals(DenyReason.CREDENTIAL_REPLAYED, replay.getReason());
        log.info("TEST|case=ssoReplay|tenant=tenant-a|subject=alice|resource=-|action=SSO_LOGIN|basis={}", replay.getReason());
    }

    @Test
    @DisplayName("刷新令牌续期后旧令牌重放被拒并吊销家族")
    void refreshRotationRejectsReplay() {
        TokenBundle bundle = authn.login("PASSWORD", "tenant-a", "alice", "pw", null);
        TokenBundle rotated = authn.refresh(bundle.refreshToken().token());
        assertNotEquals(bundle.accessToken().token(), rotated.accessToken().token());

        AccessGuardException replay = assertThrows(AccessGuardException.class,
                () -> authn.refresh(bundle.refreshToken().token()));
        assertEquals(DenyReason.CREDENTIAL_REPLAYED, replay.getReason());

        // the newly issued chain is also unusable once the family is revoked
        AccessGuardException revoked = assertThrows(AccessGuardException.class,
                () -> authn.refresh(rotated.refreshToken().token()));
        assertEquals(DenyReason.CREDENTIAL_REVOKED, revoked.getReason());
        log.info("TEST|case=refreshReplay|tenant=tenant-a|subject=alice|resource=-|action=REFRESH|basis={} then {}",
                replay.getReason(), revoked.getReason());
    }

    @Test
    @DisplayName("过期刷新令牌 -> CREDENTIAL_EXPIRED（不触发家族吊销）")
    void expiredRefreshToken() {
        TokenBundle bundle = authn.login("PASSWORD", "tenant-a", "alice", "pw", null);
        clock.advance(3_001L);
        AccessGuardException ex = assertThrows(AccessGuardException.class,
                () -> authn.refresh(bundle.refreshToken().token()));
        assertEquals(DenyReason.CREDENTIAL_EXPIRED, ex.getReason());
        log.info("TEST|case=expiredRefresh|tenant=tenant-a|subject=alice|resource=-|action=REFRESH|basis={}", ex.getReason());
    }

    @Test
    @DisplayName("并发续期同一刷新令牌：仅一次成功，其余拒绝，且家族被吊销")
    void concurrentRefreshExactlyOneWins() throws Exception {
        TokenBundle bundle = authn.login("PASSWORD", "tenant-a", "alice", "pw", null);
        String rt = bundle.refreshToken().token();

        int threads = 16;
        ExecutorService pool = Executors.newFixedThreadPool(threads);
        CountDownLatch start = new CountDownLatch(1);
        AtomicInteger ok = new AtomicInteger();
        AtomicInteger replay = new AtomicInteger();

        for (int i = 0; i < threads; i++) {
            pool.submit(() -> {
                try {
                    start.await();
                    try {
                        authn.refresh(rt);
                        ok.incrementAndGet();
                    } catch (AccessGuardException ex) {
                        if (ex.getReason() == DenyReason.CREDENTIAL_REPLAYED
                                || ex.getReason() == DenyReason.CREDENTIAL_REVOKED) {
                            replay.incrementAndGet();
                        }
                    }
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                }
            });
        }
        start.countDown();
        pool.shutdown();
        assertTrue(pool.awaitTermination(10, TimeUnit.SECONDS));
        assertEquals(1, ok.get());
        assertEquals(threads - 1, replay.get());
        log.info("TEST|case=concurrentRefresh|tenant=tenant-a|subject=alice|resource=-|action=REFRESH|basis=ok=1 rejected={}", replay.get());
    }

    @Test
    @DisplayName("连续登录失败触发锁定，锁定期满自动恢复")
    void loginFailureLocksThenRecovers() {
        for (int i = 0; i < 2; i++) {
            AccessGuardException ex = assertThrows(AccessGuardException.class,
                    () -> authn.login("PASSWORD", "tenant-a", "alice", "wrong", null));
            assertEquals(DenyReason.BAD_CREDENTIALS, ex.getReason());
        }
        AccessGuardException locked = assertThrows(AccessGuardException.class,
                () -> authn.login("PASSWORD", "tenant-a", "alice", "wrong", null));
        assertEquals(DenyReason.ACCOUNT_LOCKED, locked.getReason());

        // even the correct password is refused while locked
        AccessGuardException stillLocked = assertThrows(AccessGuardException.class,
                () -> authn.login("PASSWORD", "tenant-a", "alice", "pw", null));
        assertEquals(DenyReason.ACCOUNT_LOCKED, stillLocked.getReason());

        clock.advance(120_001L);
        TokenBundle after = authn.login("PASSWORD", "tenant-a", "alice", "pw", null);
        assertTrue(after.accessToken().token().startsWith("ey") || after.accessToken().token().length() > 20);
        log.info("TEST|case=loginLockRecovery|tenant=tenant-a|subject=alice|resource=-|action=LOGIN|basis=locked then recovered after ttl");
    }
}
