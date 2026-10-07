package com.github.xingjianluo.multitenantaccessguardjava.web;

import com.github.xingjianluo.multitenantaccessguardjava.audit.AuditEvent;
import com.github.xingjianluo.multitenantaccessguardjava.audit.AuditLog;
import com.github.xingjianluo.multitenantaccessguardjava.domain.AccessDecision;
import com.github.xingjianluo.multitenantaccessguardjava.domain.Action;
import com.github.xingjianluo.multitenantaccessguardjava.domain.AuthContext;
import com.github.xingjianluo.multitenantaccessguardjava.domain.DenyReason;
import com.github.xingjianluo.multitenantaccessguardjava.lockout.LockoutResult;
import com.github.xingjianluo.multitenantaccessguardjava.lockout.SensitiveActionLockout;
import com.github.xingjianluo.multitenantaccessguardjava.policy.AccessEvaluator;
import com.github.xingjianluo.multitenantaccessguardjava.ratelimit.RateLimitResult;
import com.github.xingjianluo.multitenantaccessguardjava.ratelimit.RateLimiter;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;

/** 受保护资源端点：读 / 写 / 删；写删为敏感操作，受限流与临时锁定约束。 */
@RestController
@RequestMapping("/api/resources")
public class ResourceController {

    private final AccessEvaluator evaluator;
    private final RateLimiter rateLimiter;
    private final SensitiveActionLockout lockout;
    private final AuditLog auditLog;

    public ResourceController(AccessEvaluator evaluator, RateLimiter rateLimiter,
                              SensitiveActionLockout lockout, AuditLog auditLog) {
        this.evaluator = evaluator;
        this.rateLimiter = rateLimiter;
        this.lockout = lockout;
        this.auditLog = auditLog;
    }

    @GetMapping("/{id}")
    public ResponseEntity<Map<String, Object>> read(@PathVariable String id, HttpServletRequest request) {
        return guard(id, Action.READ, request);
    }

    @PutMapping("/{id}")
    public ResponseEntity<Map<String, Object>> write(@PathVariable String id, HttpServletRequest request) {
        return guard(id, Action.WRITE, request);
    }

    @DeleteMapping("/{id}")
    public ResponseEntity<Map<String, Object>> delete(@PathVariable String id, HttpServletRequest request) {
        return guard(id, Action.DELETE, request);
    }

    private ResponseEntity<Map<String, Object>> guard(String resourceId, Action action,
                                                      HttpServletRequest request) {
        AuthContext context = (AuthContext) request.getAttribute(AuthFilter.ATTR_AUTH_CONTEXT);
        if (context == null) {
            return error(HttpStatus.UNAUTHORIZED, DenyReason.UNAUTHENTICATED, action);
        }
        String subjectKey = "sensitive:" + context.subject().tenantId() + ":" + context.subject().userId();

        if (action == Action.READ) {
            return respond(evaluator.evaluate(context, resourceId, action), action, resourceId);
        }

        // 敏感操作：同一主体整段串行化——查锁定、限流计数、权限判定、失败记录之间
        // 不会被并发插入，杜绝“已锁定还被放行”与计数丢失。
        synchronized (lockout.lockFor(subjectKey)) {
            LockoutResult lockState = lockout.checkLocked(subjectKey);
            if (lockState.locked()) {
                audit(context, resourceId, action, DenyReason.SENSITIVE_LOCKED,
                        "sensitive action blocked until " + lockState.lockedUntil());
                return error(HttpStatus.TOO_MANY_REQUESTS, DenyReason.SENSITIVE_LOCKED, action);
            }
            RateLimitResult limit = rateLimiter.check(subjectKey);
            if (limit.locked()) {
                audit(context, resourceId, action, DenyReason.LOCKED, "rate lock active");
                return error(HttpStatus.TOO_MANY_REQUESTS, DenyReason.LOCKED, action);
            }
            if (!limit.permitted()) {
                audit(context, resourceId, action, DenyReason.RATE_LIMITED, "sensitive action rate limited");
                return error(HttpStatus.TOO_MANY_REQUESTS, DenyReason.RATE_LIMITED, action);
            }
            AccessDecision decision = evaluator.evaluate(context, resourceId, action);
            if (decision.allowed()) {
                // 成功执行：清零此前的连续失败，并重置本窗口敏感操作计数（与登录成功语义一致）
                lockout.reset(subjectKey);
                rateLimiter.reset(subjectKey);
            } else {
                LockoutResult afterFailure = lockout.recordFailure(subjectKey);
                if (afterFailure.locked()) {
                    audit(context, resourceId, action, DenyReason.SENSITIVE_LOCKED,
                            "threshold reached after denied " + action + ", locked until "
                                    + afterFailure.lockedUntil());
                    return error(HttpStatus.TOO_MANY_REQUESTS, DenyReason.SENSITIVE_LOCKED, action);
                }
            }
            return respond(decision, action, resourceId);
        }
    }

    private ResponseEntity<Map<String, Object>> respond(AccessDecision decision, Action action,
                                                        String resourceId) {
        if (!decision.allowed()) {
            HttpStatus status = decision.denyReason() == DenyReason.RESOURCE_NOT_FOUND
                    ? HttpStatus.NOT_FOUND : HttpStatus.FORBIDDEN;
            return error(status, decision.denyReason(), action);
        }
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("result", "OK");
        body.put("action", action.name());
        body.put("resource", resourceId);
        return ResponseEntity.ok(body);
    }

    private void audit(AuthContext context, String resourceId, Action action,
                       DenyReason reason, String basis) {
        auditLog.record(new AuditEvent(Instant.now(),
                context.subject().userId(), context.subject().tenantId(),
                resourceId, action, false, reason, basis));
    }

    private static ResponseEntity<Map<String, Object>> error(HttpStatus status, DenyReason reason,
                                                             Action action) {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("error", status.name());
        body.put("reason", reason.name());
        body.put("action", action.name());
        return ResponseEntity.status(status).body(body);
    }
}
