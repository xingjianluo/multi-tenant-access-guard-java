package com.github.xingjianluo.multitenantaccessguardjava.auth;

import com.github.xingjianluo.multitenantaccessguardjava.audit.AuditEvent;
import com.github.xingjianluo.multitenantaccessguardjava.audit.AuditService;
import com.github.xingjianluo.multitenantaccessguardjava.model.DenyReason;
import com.github.xingjianluo.multitenantaccessguardjava.model.LoginEntry;
import com.github.xingjianluo.multitenantaccessguardjava.model.Subject;
import com.github.xingjianluo.multitenantaccessguardjava.ratelimit.RateLimitService;
import com.github.xingjianluo.multitenantaccessguardjava.ratelimit.RateResult;
import com.github.xingjianluo.multitenantaccessguardjava.support.AccessGuardException;
import com.github.xingjianluo.multitenantaccessguardjava.support.TimeSource;
import org.springframework.stereotype.Service;

import java.util.UUID;

/**
 * Authentication facade shared by the two login entries.
 *
 * <p>Consistency and safety properties:
 * <ul>
 *   <li><b>Entry convergence</b>: PASSWORD and SSO both yield a Subject keyed only by
 *       (tenantId, subjectId); tokens carry identity only, never roles, so downstream
 *       authorization is identical and always reflects current permissions.</li>
 *   <li><b>Failure lockout</b>: failed logins are counted per (tenant, subject/key);
 *       a locked key is rejected before credential verification with
 *       {@link DenyReason#ACCOUNT_LOCKED}.</li>
 *   <li><b>Expiry vs tamper</b>: signature verification failure is
 *       INVALID_CREDENTIAL; a valid signature past expiry is CREDENTIAL_EXPIRED.</li>
 *   <li><b>Concurrent renewal</b>: refresh-token consumption is atomic in
 *       {@link RefreshStore}; duplicate/concurrent renewal cannot double-issue, and a
 *       replay revokes the whole family (CREDENTIAL_REPLAYED / CREDENTIAL_REVOKED).</li>
 * </ul>
 */
@Service
public class DefaultAuthenticationService implements AuthenticationService {

    private final TokenService tokenService;
    private final RefreshStore refreshStore;
    private final CredentialService credentialService;
    private final RateLimitService rateLimitService;
    private final AuditService auditService;
    private final TimeSource timeSource;

    public DefaultAuthenticationService(TokenService tokenService,
                                        RefreshStore refreshStore,
                                        CredentialService credentialService,
                                        RateLimitService rateLimitService,
                                        AuditService auditService,
                                        TimeSource timeSource) {
        this.tokenService = tokenService;
        this.refreshStore = refreshStore;
        this.credentialService = credentialService;
        this.rateLimitService = rateLimitService;
        this.auditService = auditService;
        this.timeSource = timeSource;
    }

    @Override
    public TokenBundle login(String entry, String tenantId, String username,
                             String password, String assertionId) {
        long now = timeSource.nowMillis();
        LoginEntry loginEntry;
        try {
            loginEntry = LoginEntry.valueOf(entry == null ? "" : entry.trim().toUpperCase());
        } catch (IllegalArgumentException e) {
            throw new AccessGuardException(DenyReason.UNSUPPORTED_ENTRY, "unknown login entry: " + entry);
        }

        String lockKey = "login:" + tenantId + ":"
                + (loginEntry == LoginEntry.PASSWORD ? username : "sso-" + assertionId);
        RateResult gate = rateLimitService.check(lockKey, now);
        if (!gate.allowed()) {
            auditLogin(tenantId, username, loginEntry, false, DenyReason.ACCOUNT_LOCKED,
                    "locked; retryAfterMillis=" + gate.retryAfterMillis(), null);
            throw new AccessGuardException(DenyReason.ACCOUNT_LOCKED,
                    "temporarily locked due to repeated failures");
        }

        Subject subject;
        try {
            subject = switch (loginEntry) {
                case PASSWORD -> credentialService.verifyPassword(tenantId, username, password);
                case SSO -> credentialService.verifySsoAssertion(assertionId);
            };
        } catch (AccessGuardException ex) {
            RateResult after = rateLimitService.penalize(lockKey, now);
            DenyReason effective = after.allowed() ? ex.getReason() : DenyReason.ACCOUNT_LOCKED;
            auditLogin(tenantId, username, loginEntry, false, effective,
                    ex.getMessage() + (after.allowed() ? "" : "; lock engaged"), null);
            throw new AccessGuardException(effective,
                    after.allowed() ? ex.getMessage() : "temporarily locked due to repeated failures");
        }

        rateLimitService.reset(lockKey);
        TokenBundle bundle = issueBundle(subject, now);
        auditLogin(subject.tenantId(), subject.subjectId(), loginEntry, true, null,
                "login ok family=" + bundle.refreshToken().payload().familyId(),
                bundle.accessToken().payload().tokenId());
        return bundle;
    }

    @Override
    public TokenBundle refresh(String refreshToken) {
        long now = timeSource.nowMillis();
        TokenPayload oldPayload;
        try {
            oldPayload = tokenService.verifySignature(refreshToken);
        } catch (AccessGuardException ex) {
            auditRefresh(null, false, ex.getReason(), "tampered refresh credential");
            throw ex;
        }
        if (!TokenPayload.TYPE_REFRESH.equals(oldPayload.type())) {
            auditRefresh(oldPayload, false, DenyReason.INVALID_CREDENTIAL, "not a refresh token");
            throw new AccessGuardException(DenyReason.INVALID_CREDENTIAL, "wrong token type");
        }
        if (oldPayload.expiresAt() <= now) {
            auditRefresh(oldPayload, false, DenyReason.CREDENTIAL_EXPIRED,
                    "refresh token expired at " + oldPayload.expiresAt());
            throw new AccessGuardException(DenyReason.CREDENTIAL_EXPIRED, "refresh token expired");
        }

        // Tentative next token ids are decided first; the store performs the single
        // atomic consume-or-detect-replay transition.
        String familyId = oldPayload.familyId();
        IssuedToken nextAccess = tokenService.issueAccess(
                oldPayload.tenantId(), oldPayload.subjectId(), oldPayload.loginEntry(), familyId, now);
        IssuedToken nextRefresh = tokenService.issueRefresh(
                oldPayload.tenantId(), oldPayload.subjectId(), oldPayload.loginEntry(), familyId, now);

        RefreshVerdict verdict = refreshStore.consume(oldPayload.tokenId(),
                nextRefresh.payload().tokenId(), nextRefresh.payload().expiresAt(), now);
        switch (verdict.status()) {
            case OK -> {
                auditRefresh(oldPayload, true, null, "rotated to " + nextRefresh.payload().tokenId());
                return new TokenBundle(nextAccess, nextRefresh);
            }
            case REPLAY, REVOKED -> {
                auditRefresh(oldPayload, false, verdict.denyReason(),
                        "refresh family " + familyId + " revoked after reuse");
                throw new AccessGuardException(verdict.denyReason(),
                        "refresh token rejected; session family revoked");
            }
            case UNKNOWN -> {
                auditRefresh(oldPayload, false, DenyReason.INVALID_CREDENTIAL, "unknown refresh token");
                throw new AccessGuardException(DenyReason.INVALID_CREDENTIAL, "unknown refresh token");
            }
            default -> throw new IllegalStateException("unexpected verdict");
        }
    }

    @Override
    public Subject authenticate(String authorizationHeader) {
        long now = timeSource.nowMillis();
        if (authorizationHeader == null || !authorizationHeader.startsWith("Bearer ")) {
            throw new AccessGuardException(DenyReason.UNAUTHENTICATED, "Bearer token required");
        }
        String token = authorizationHeader.substring("Bearer ".length()).trim();
        TokenPayload payload;
        try {
            payload = tokenService.verifySignature(token);
        } catch (AccessGuardException ex) {
            auditAuthn(null, false, ex.getReason(), "signature verification failed");
            throw ex;
        }
        if (!TokenPayload.TYPE_ACCESS.equals(payload.type())) {
            auditAuthn(payload, false, DenyReason.INVALID_CREDENTIAL, "wrong token type");
            throw new AccessGuardException(DenyReason.INVALID_CREDENTIAL, "wrong token type");
        }
        if (payload.expiresAt() <= now) {
            auditAuthn(payload, false, DenyReason.CREDENTIAL_EXPIRED,
                    "expired at " + payload.expiresAt());
            throw new AccessGuardException(DenyReason.CREDENTIAL_EXPIRED, "credential expired");
        }
        Subject subject = new Subject(payload.tenantId(), payload.subjectId(), payload.loginEntry());
        auditAuthn(payload, true, null, "access token accepted");
        return subject;
    }

    private TokenBundle issueBundle(Subject subject, long now) {
        String familyId = UUID.randomUUID().toString();
        IssuedToken access = tokenService.issueAccess(
                subject.tenantId(), subject.subjectId(), subject.loginEntry(), familyId, now);
        IssuedToken refresh = tokenService.issueRefresh(
                subject.tenantId(), subject.subjectId(), subject.loginEntry(), familyId, now);
        refreshStore.save(new RefreshRecord(familyId, refresh.payload().tokenId(),
                subject.tenantId(), subject.subjectId(), subject.loginEntry(),
                refresh.payload().expiresAt(), false, false));
        return new TokenBundle(access, refresh);
    }

    private void auditLogin(String tenantId, String subjectId, LoginEntry entry,
                            boolean allowed, DenyReason reason, String basis, String tokenId) {
        auditService.record(new AuditEvent(timeSource.nowMillis(), "LOGIN",
                tenantId, subjectId, entry == null ? null : entry.name(), null, null,
                allowed, reason == null ? "ALLOW" : reason.name(), basis, null,
                tokenId == null ? UUID.randomUUID().toString() : tokenId));
    }

    private void auditRefresh(TokenPayload payload, boolean allowed, DenyReason reason, String basis) {
        auditService.record(new AuditEvent(timeSource.nowMillis(), "REFRESH",
                payload == null ? null : payload.tenantId(),
                payload == null ? null : payload.subjectId(),
                payload == null ? null : payload.loginEntry().name(),
                null, null, allowed, reason == null ? "ALLOW" : reason.name(), basis, null,
                UUID.randomUUID().toString()));
    }

    private void auditAuthn(TokenPayload payload, boolean allowed, DenyReason reason, String basis) {
        auditService.record(new AuditEvent(timeSource.nowMillis(), "AUTHN",
                payload == null ? null : payload.tenantId(),
                payload == null ? null : payload.subjectId(),
                payload == null ? null : payload.loginEntry().name(),
                null, null, allowed, reason == null ? "ALLOW" : reason.name(), basis, null,
                UUID.randomUUID().toString()));
    }
}
