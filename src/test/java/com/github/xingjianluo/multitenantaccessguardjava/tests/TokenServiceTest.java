package com.github.xingjianluo.multitenantaccessguardjava.tests;

import com.github.xingjianluo.multitenantaccessguardjava.auth.AuthToken;
import com.github.xingjianluo.multitenantaccessguardjava.auth.CredentialException;
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
        tokens = new TokenService(directory, clock, 60, "test-secret");
    }

    @Test
    void validTokenAuthenticates() {
        AuthToken token = tokens.issue("u-alice", "tenant-a");
        AuthContext ctx = tokens.authenticate(token.serialized());
        assertEquals("u-alice", ctx.subject().userId());
        assertEquals("tenant-a", ctx.subject().tenantId());
    }

    @Test
    void expiredTokenIsRejected() {
        AuthToken token = tokens.issue("u-alice", "tenant-a");
        clock.advance(Duration.ofSeconds(61));
        CredentialException e = assertThrows(CredentialException.class,
                () -> tokens.authenticate(token.serialized()));
        log.info("TEST-CRED subject=u-alice tenant=tenant-a reason={}", e.reason());
        assertEquals(DenyReason.CREDENTIAL_EXPIRED, e.reason());
    }

    @Test
    void tamperedTokenIsRejected() {
        AuthToken token = tokens.issue("u-alice", "tenant-a");
        // 篡改 payload 中一个字符（签名不变）
        int dot = token.serialized().lastIndexOf('.');
        String body = token.serialized().substring(0, dot);
        char c = body.charAt(5);
        char flipped = c == 'A' ? 'B' : 'A';
        String tampered = body.substring(0, 5) + flipped + body.substring(6)
                + token.serialized().substring(dot);
        CredentialException e = assertThrows(CredentialException.class,
                () -> tokens.authenticate(tampered));
        log.info("TEST-CRED subject=u-alice tenant=tenant-a reason={}", e.reason());
        assertEquals(DenyReason.CREDENTIAL_TAMPERED, e.reason());
    }

    @Test
    void oldTokenAfterRefreshIsReplay() {
        AuthToken old = tokens.issue("u-alice", "tenant-a");
        AuthToken rotated = tokens.refresh(old.serialized());
        assertNotEquals(old.tokenId(), rotated.tokenId());
        // 旧令牌再用于认证 → 重放
        CredentialException e = assertThrows(CredentialException.class,
                () -> tokens.authenticate(old.serialized()));
        assertEquals(DenyReason.CREDENTIAL_REPLAYED, e.reason());
        // 旧令牌再次续期 → 重放
        assertEquals(DenyReason.CREDENTIAL_REPLAYED,
                assertThrows(CredentialException.class,
                        () -> tokens.refresh(old.serialized())).reason());
        // 新令牌正常可用
        assertEquals("u-alice", tokens.authenticate(rotated.serialized()).subject().userId());
    }

    @Test
    void concurrentRefreshOnlyOneSucceeds() throws Exception {
        AuthToken token = tokens.issue("u-alice", "tenant-a");
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
                    tokens.refresh(token.serialized());
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
        log.info("TEST-REFRESH subject=u-alice tenant=tenant-a success={} replayed={}",
                success.get(), replayed.get());
        assertEquals(1, success.get(), "并发续期只能有一个成功");
        assertEquals(threads - 1, replayed.get(), "其余必须判定为重放");
    }

    @Test
    void roleChangeTakesEffectWithoutReissue() {
        AuthToken token = tokens.issue("u-alice", "tenant-a");
        // 权限变更：目录中该用户角色被调整
        directory.register("alice", "pw", new Subject("u-alice", "tenant-a", Set.of(Role.ADMIN)));
        AuthContext ctx = tokens.authenticate(token.serialized());
        assertEquals(Set.of(Role.ADMIN), ctx.subject().roles(), "角色实时加载，旧权限不残留");
    }
}
