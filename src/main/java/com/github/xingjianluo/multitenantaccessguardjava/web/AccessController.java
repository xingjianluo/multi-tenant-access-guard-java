package com.github.xingjianluo.multitenantaccessguardjava.web;

import com.github.xingjianluo.multitenantaccessguardjava.audit.AuditEvent;
import com.github.xingjianluo.multitenantaccessguardjava.audit.AuditService;
import com.github.xingjianluo.multitenantaccessguardjava.auth.AuthenticationService;
import com.github.xingjianluo.multitenantaccessguardjava.authz.AuthorizationService;
import com.github.xingjianluo.multitenantaccessguardjava.model.Action;
import com.github.xingjianluo.multitenantaccessguardjava.model.Decision;
import com.github.xingjianluo.multitenantaccessguardjava.model.DenyReason;
import com.github.xingjianluo.multitenantaccessguardjava.model.Subject;
import com.github.xingjianluo.multitenantaccessguardjava.ratelimit.RateLimitPolicy;
import com.github.xingjianluo.multitenantaccessguardjava.ratelimit.RateLimitService;
import com.github.xingjianluo.multitenantaccessguardjava.ratelimit.RateResult;
import com.github.xingjianluo.multitenantaccessguardjava.support.AccessGuardException;
import com.github.xingjianluo.multitenantaccessguardjava.support.TimeSource;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.UUID;

/**
 * Resource access endpoints. Authentication (entry-independent) precedes authorization
 * against the current permission snapshot. DELETE is additionally a sensitive action:
 * it is gated by its own rate-limit policy and, when the caller simulates a rejected
 * attempt, counts a failure that can trigger a temporary lock.
 */
@RestController
@RequestMapping("/api/tenants/{tenantId}/resources/{resourceId}")
public class AccessController {

    private final AuthenticationService authenticationService;
    private final AuthorizationService authorizationService;
    private final RateLimitService rateLimitService;
    private final AuditService auditService;
    private final TimeSource timeSource;
    private final RateLimitPolicy sensitivePolicy;

    public AccessController(AuthenticationService authenticationService,
                            AuthorizationService authorizationService,
                            RateLimitService rateLimitService,
                            AuditService auditService,
                            TimeSource timeSource,
                            @Qualifier("sensitivePolicy") RateLimitPolicy sensitivePolicy) {
        this.authenticationService = authenticationService;
        this.authorizationService = authorizationService;
        this.rateLimitService = rateLimitService;
        this.auditService = auditService;
        this.timeSource = timeSource;
        this.sensitivePolicy = sensitivePolicy;
    }

    public record AccessResponse(boolean allowed, String tenantId, String subjectId,
                                 String resourceId, String action, String basis,
                                 long snapshotVersion) {
    }

    private AccessResponse doAccess(String authorizationHeader, String tenantId,
                                    String resourceId, Action action, boolean sensitive) {
        long now = timeSource.nowMillis();
        Subject subject = authenticationService.authenticate(authorizationHeader);

        if (sensitive) {
            String key = "sensitive:" + subject.tenantId() + ":" + subject.subjectId();
            RateResult gate = rateLimitService.check(key, now);
            if (!gate.allowed()) {
                auditSensitive(subject, resourceId, action, false, DenyReason.RATE_LIMITED,
                        "sensitive action locked; retryAfterMillis=" + gate.retryAfterMillis());
                throw new AccessGuardException(DenyReason.RATE_LIMITED,
                        "too many sensitive operations; try again later");
            }
        }

        Decision decision = authorizationService.authorize(subject, tenantId, resourceId, action);

        if (sensitive && !decision.allowed()) {
            // A denied sensitive attempt counts toward the sensitive-action lock.
            String key = "sensitive:" + subject.tenantId() + ":" + subject.subjectId();
            RateResult after = rateLimitService.penalize(key, now);
            if (!after.allowed()) {
                auditSensitive(subject, resourceId, action, false, DenyReason.RATE_LIMITED,
                        "sensitive action lock engaged after denial");
                throw new AccessGuardException(DenyReason.RATE_LIMITED,
                        "too many sensitive operations; try again later");
            }
        }

        if (!decision.allowed()) {
            throw new AccessGuardException(decision.reason(), decision.basis());
        }

        return new AccessResponse(true, subject.tenantId(), subject.subjectId(),
                resourceId, action.name(), decision.basis(), decision.snapshotVersion());
    }

    @PostMapping("/read")
    public AccessResponse read(@RequestHeader("Authorization") String authorizationHeader,
                               @PathVariable String tenantId,
                               @PathVariable String resourceId) {
        return doAccess(authorizationHeader, tenantId, resourceId, Action.READ, false);
    }

    @PostMapping("/write")
    public AccessResponse write(@RequestHeader("Authorization") String authorizationHeader,
                                @PathVariable String tenantId,
                                @PathVariable String resourceId) {
        return doAccess(authorizationHeader, tenantId, resourceId, Action.WRITE, false);
    }

    @PostMapping("/delete")
    public AccessResponse delete(@RequestHeader("Authorization") String authorizationHeader,
                                 @PathVariable String tenantId,
                                 @PathVariable String resourceId,
                                 @RequestParam(name = "simulateFailure", defaultValue = "false")
                                 boolean simulateFailure) {
        // simulateFailure lets tests drive denied sensitive attempts without mutating data.
        if (simulateFailure) {
            long now = timeSource.nowMillis();
            Subject subject = authenticationService.authenticate(authorizationHeader);
            String key = "sensitive:" + subject.tenantId() + ":" + subject.subjectId();
            RateResult gate = rateLimitService.check(key, now);
            if (!gate.allowed()) {
                auditSensitive(subject, resourceId, Action.DELETE, false,
                        DenyReason.RATE_LIMITED,
                        "sensitive action locked; retryAfterMillis=" + gate.retryAfterMillis());
                throw new AccessGuardException(DenyReason.RATE_LIMITED,
                        "too many sensitive operations; try again later");
            }
            RateResult after = rateLimitService.penalize(key, now);
            boolean locked = !after.allowed();
            auditSensitive(subject, resourceId, Action.DELETE, false,
                    locked ? DenyReason.RATE_LIMITED : DenyReason.FORBIDDEN,
                    "simulated sensitive failure " + after.failures() + "/"
                            + sensitivePolicy.maxFailures());
            throw new AccessGuardException(locked ? DenyReason.RATE_LIMITED : DenyReason.FORBIDDEN,
                    locked ? "too many sensitive operations; try again later"
                           : "simulated sensitive failure");
        }
        return doAccess(authorizationHeader, tenantId, resourceId, Action.DELETE, true);
    }

    private void auditSensitive(Subject subject, String resourceId, Action action,
                                boolean allowed, DenyReason reason, String basis) {
        auditService.record(new AuditEvent(timeSource.nowMillis(), "SENSITIVE",
                subject.tenantId(), subject.subjectId(),
                subject.loginEntry() == null ? null : subject.loginEntry().name(),
                resourceId, action.name(), allowed, reason.name(), basis, null,
                UUID.randomUUID().toString()));
    }
}
