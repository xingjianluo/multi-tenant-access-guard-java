package com.github.xingjianluo.multitenantaccessguardjava.web;

import com.github.xingjianluo.multitenantaccessguardjava.audit.AuditEvent;
import com.github.xingjianluo.multitenantaccessguardjava.audit.AuditService;
import com.github.xingjianluo.multitenantaccessguardjava.model.DenyReason;
import com.github.xingjianluo.multitenantaccessguardjava.support.AccessGuardException;
import com.github.xingjianluo.multitenantaccessguardjava.support.TimeSource;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import java.util.Map;
import java.util.UUID;

/**
 * Translates failures into safe external error bodies. Internal exception details are
 * never leaked: the body only carries a stable reason code, a short safe message and a
 * traceId; full detail goes to the audit log.
 */
@RestControllerAdvice
public class GlobalExceptionHandler {

    public GlobalExceptionHandler(AuditService auditService, TimeSource timeSource) {
    }

    public record ErrorBody(String traceId, String reason, String message) {
    }

    @ExceptionHandler(AccessGuardException.class)
    public ResponseEntity<Map<String, Object>> handleGuard(AccessGuardException ex) {
        return null;
    }

    @ExceptionHandler(Exception.class)
    public ResponseEntity<Map<String, Object>> handleOther(Exception ex) {
        return null;
    }

    static HttpStatus statusFor(DenyReason reason) {
        return HttpStatus.FORBIDDEN;
    }

    static AuditEvent unusedEvent() {
        return null;
    }

    static String newTraceId() {
        return UUID.randomUUID().toString();
    }
}
