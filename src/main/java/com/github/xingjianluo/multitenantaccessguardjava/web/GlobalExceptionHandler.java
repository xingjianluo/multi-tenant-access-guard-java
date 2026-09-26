package com.github.xingjianluo.multitenantaccessguardjava.web;

import com.github.xingjianluo.multitenantaccessguardjava.audit.AuditEvent;
import com.github.xingjianluo.multitenantaccessguardjava.audit.AuditService;
import com.github.xingjianluo.multitenantaccessguardjava.model.DenyReason;
import com.github.xingjianluo.multitenantaccessguardjava.support.AccessGuardException;
import com.github.xingjianluo.multitenantaccessguardjava.support.TimeSource;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import java.util.Map;
import java.util.UUID;

/**
 * Single translation point from failures to external error bodies.
 *
 * <p>Callers only ever see {@code {traceId, reason, message}} with a stable,
 * distinguishable reason code and a short safe message. Exception class names, stack
 * traces and internal state are written to the audit/server log only and never
 * serialized to the response.
 */
@RestControllerAdvice
public class GlobalExceptionHandler {

    private static final Logger log = LoggerFactory.getLogger(GlobalExceptionHandler.class);

    private final AuditService auditService;
    private final TimeSource timeSource;

    public GlobalExceptionHandler(AuditService auditService, TimeSource timeSource) {
        this.auditService = auditService;
        this.timeSource = timeSource;
    }

    @ExceptionHandler(AccessGuardException.class)
    public ResponseEntity<Map<String, Object>> handleGuard(AccessGuardException ex) {
        String traceId = newTraceId();
        auditService.record(new AuditEvent(timeSource.nowMillis(), "DENIED",
                null, null, null, null, null, false,
                ex.getReason().name(), ex.getMessage(), null, traceId));
        return ResponseEntity.status(statusFor(ex.getReason())).body(Map.of(
                "traceId", traceId,
                "reason", ex.getReason().name(),
                "message", safeMessage(ex.getReason())));
    }

    @ExceptionHandler({HttpMessageNotReadableException.class, IllegalArgumentException.class})
    public ResponseEntity<Map<String, Object>> handleBadRequest(Exception ex) {
        String traceId = newTraceId();
        auditService.record(new AuditEvent(timeSource.nowMillis(), "BAD_REQUEST",
                null, null, null, null, null, false,
                "BAD_REQUEST", ex.getClass().getSimpleName(), null, traceId));
        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(Map.of(
                "traceId", traceId,
                "reason", "BAD_REQUEST",
                "message", "request body is malformed or invalid"));
    }

    @ExceptionHandler(Exception.class)
    public ResponseEntity<Map<String, Object>> handleOther(Exception ex) {
        String traceId = newTraceId();
        // Full internal detail goes server-side only.
        log.error("internal error trace={}", traceId, ex);
        auditService.record(new AuditEvent(timeSource.nowMillis(), "INTERNAL_ERROR",
                null, null, null, null, null, false,
                "INTERNAL_ERROR", ex.getClass().getSimpleName() + ": " + ex.getMessage(),
                null, traceId));
        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(Map.of(
                "traceId", traceId,
                "reason", "INTERNAL_ERROR",
                "message", "request failed; contact support with traceId " + traceId));
    }

    static HttpStatus statusFor(DenyReason reason) {
        return switch (reason) {
            case UNAUTHENTICATED, INVALID_CREDENTIAL, CREDENTIAL_EXPIRED,
                 CREDENTIAL_REPLAYED, CREDENTIAL_REVOKED, BAD_CREDENTIALS -> HttpStatus.UNAUTHORIZED;
            case ACCOUNT_LOCKED, RATE_LIMITED -> HttpStatus.TOO_MANY_REQUESTS;
            case CROSS_TENANT_ACCESS, FORBIDDEN -> HttpStatus.FORBIDDEN;
            case RESOURCE_NOT_FOUND -> HttpStatus.NOT_FOUND;
            case UNSUPPORTED_ENTRY -> HttpStatus.BAD_REQUEST;
        };
    }

    /** External-safe message: no account existence, stack trace or internal detail. */
    private static String safeMessage(DenyReason reason) {
        return switch (reason) {
            case RESOURCE_NOT_FOUND -> "resource not found";
            case CROSS_TENANT_ACCESS -> "cross-tenant access denied";
            case FORBIDDEN -> "operation not permitted for this subject";
            case UNAUTHENTICATED -> "authentication required";
            case INVALID_CREDENTIAL -> "credential is invalid";
            case CREDENTIAL_EXPIRED -> "credential has expired";
            case CREDENTIAL_REPLAYED -> "credential replay detected; session revoked";
            case CREDENTIAL_REVOKED -> "credential has been revoked";
            case BAD_CREDENTIALS -> "invalid credentials";
            case UNSUPPORTED_ENTRY -> "unsupported login entry";
            case ACCOUNT_LOCKED -> "account temporarily locked due to repeated failures";
            case RATE_LIMITED -> "too many sensitive operations; try again later";
        };
    }

    static String newTraceId() {
        return UUID.randomUUID().toString();
    }
}
