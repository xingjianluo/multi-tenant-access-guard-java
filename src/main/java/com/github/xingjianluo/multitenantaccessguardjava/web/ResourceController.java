package com.github.xingjianluo.multitenantaccessguardjava.web;

import com.github.xingjianluo.multitenantaccessguardjava.domain.AccessDecision;
import com.github.xingjianluo.multitenantaccessguardjava.domain.Action;
import com.github.xingjianluo.multitenantaccessguardjava.domain.AuthContext;
import com.github.xingjianluo.multitenantaccessguardjava.domain.DenyReason;
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

import java.util.LinkedHashMap;
import java.util.Map;

/** 受保护资源端点：读 / 写 / 删；写删为敏感操作，受限流与锁定约束。 */
@RestController
@RequestMapping("/api/resources")
public class ResourceController {

    private final AccessEvaluator evaluator;
    private final RateLimiter rateLimiter;

    public ResourceController(AccessEvaluator evaluator, RateLimiter rateLimiter) {
        this.evaluator = evaluator;
        this.rateLimiter = rateLimiter;
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
        if (action != Action.READ) {
            RateLimitResult limit = rateLimiter.check("sensitive:" + context.subject().userId());
            if (limit.locked()) {
                return error(HttpStatus.TOO_MANY_REQUESTS, DenyReason.LOCKED, action);
            }
            if (!limit.permitted()) {
                return error(HttpStatus.TOO_MANY_REQUESTS, DenyReason.RATE_LIMITED, action);
            }
        }
        AccessDecision decision = evaluator.evaluate(context, resourceId, action);
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

    private static ResponseEntity<Map<String, Object>> error(HttpStatus status, DenyReason reason,
                                                             Action action) {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("error", status.name());
        body.put("reason", reason.name());
        body.put("action", action.name());
        return ResponseEntity.status(status).body(body);
    }
}
