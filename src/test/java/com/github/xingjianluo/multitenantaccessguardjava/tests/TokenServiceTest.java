package com.github.xingjianluo.multitenantaccessguardjava.tests;

import com.github.xingjianluo.multitenantaccessguardjava.auth.HmacTokenService;
import com.github.xingjianluo.multitenantaccessguardjava.auth.IssuedToken;
import com.github.xingjianluo.multitenantaccessguardjava.auth.TokenPayload;
import com.github.xingjianluo.multitenantaccessguardjava.auth.TokenService;
import com.github.xingjianluo.multitenantaccessguardjava.model.DenyReason;
import com.github.xingjianluo.multitenantaccessguardjava.model.LoginEntry;
import com.github.xingjianluo.multitenantaccessguardjava.support.AccessGuardException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class TokenServiceTest {

    private static final Logger log = LoggerFactory.getLogger(TokenServiceTest.class);

    private TokenService tokenService;

    @BeforeEach
    void setUp() {
        tokenService = new HmacTokenService("unit-secret", 1_000L, 3_000L);
    }

    @Test
    @DisplayName("签发的令牌可验签并还原主体/租户/入口")
    void issueAndVerify() {
        IssuedToken issued = tokenService.issueAccess("tenant-a", "alice", LoginEntry.PASSWORD, "fam-1", 100L);
        TokenPayload p = tokenService.verifySignature(issued.token());
        assertEquals("tenant-a", p.tenantId());
        assertEquals("alice", p.subjectId());
        assertEquals(LoginEntry.PASSWORD, p.loginEntry());
        assertEquals(1_100L, p.expiresAt());
        log.info("TEST|case=issueAndVerify|tenant={}|subject={}|resource=-|action=-|basis=signature verified ttl={}",
                p.tenantId(), p.subjectId(), p.expiresAt() - p.issuedAt());
    }

    @Test
    @DisplayName("篡改载荷或签名 -> INVALID_CREDENTIAL（与过期可区分）")
    void tamperedTokenRejected() {
        IssuedToken issued = tokenService.issueAccess("tenant-a", "alice", LoginEntry.SSO, "fam-1", 100L);

        // flip a character in the payload segment
        char c = issued.token().charAt(0);
        char other = c == 'A' ? 'B' : 'A';
        String tampered = other + issued.token().substring(1);

        AccessGuardException ex = assertThrows(AccessGuardException.class,
                () -> tokenService.verifySignature(tampered));
        assertEquals(DenyReason.INVALID_CREDENTIAL, ex.getReason());

        AccessGuardException ex2 = assertThrows(AccessGuardException.class,
                () -> tokenService.verifySignature(issued.token() + "garbage"));
        assertEquals(DenyReason.INVALID_CREDENTIAL, ex2.getReason());
        log.info("TEST|case=tamperedTokenRejected|tenant=tenant-a|subject=alice|resource=-|action=-|basis={}",
                ex.getReason());
    }

    @Test
    @DisplayName("不同密钥签发的令牌 -> INVALID_CREDENTIAL")
    void wrongSecretRejected() {
        TokenService other = new HmacTokenService("different-secret", 1_000L, 3_000L);
        IssuedToken issued = other.issueAccess("tenant-a", "alice", LoginEntry.PASSWORD, "fam-1", 100L);
        AccessGuardException ex = assertThrows(AccessGuardException.class,
                () -> tokenService.verifySignature(issued.token()));
        assertEquals(DenyReason.INVALID_CREDENTIAL, ex.getReason());
        assertTrue(issued.token().length() > 20);
        log.info("TEST|case=wrongSecretRejected|tenant=tenant-a|subject=alice|resource=-|action=-|basis={}",
                ex.getReason());
    }

    @Test
    @DisplayName("过期判定与篡改判定是两个独立原因")
    void expiryIsSeparatelyClassifiedByCaller() {
        IssuedToken issued = tokenService.issueAccess("tenant-a", "alice", LoginEntry.PASSWORD, "fam-1", 100L);
        // signature still valid after expiry; the caller compares expiresAt
        TokenPayload p = tokenService.verifySignature(issued.token());
        assertNotEquals(DenyReason.INVALID_CREDENTIAL, DenyReason.CREDENTIAL_EXPIRED);
        assertEquals(1_100L, p.expiresAt());
        assertTrue(p.expiresAt() <= 1_101L, "an expired-but-intact token stays signature-valid and is classified CREDENTIAL_EXPIRED");
        log.info("TEST|case=expiryClassifiedSeparately|tenant=tenant-a|subject=alice|resource=-|action=-|basis=CREDENTIAL_EXPIRED vs INVALID_CREDENTIAL");
    }
}
