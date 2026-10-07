package com.github.xingjianluo.multitenantaccessguardjava.web;

import com.github.xingjianluo.multitenantaccessguardjava.audit.AuditEvent;
import com.github.xingjianluo.multitenantaccessguardjava.audit.AuditLog;
import com.github.xingjianluo.multitenantaccessguardjava.auth.CredentialException;
import com.github.xingjianluo.multitenantaccessguardjava.auth.SessionService;
import com.github.xingjianluo.multitenantaccessguardjava.auth.TokenService;
import com.github.xingjianluo.multitenantaccessguardjava.auth.UserDirectory;
import com.github.xingjianluo.multitenantaccessguardjava.domain.DenyReason;
import com.github.xingjianluo.multitenantaccessguardjava.domain.Subject;
import com.github.xingjianluo.multitenantaccessguardjava.ratelimit.RateLimitResult;
import com.github.xingjianluo.multitenantaccessguardjava.ratelimit.RateLimiter;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Optional;

/** 登录与续期端点：令牌入口 / 会话入口，登录失败计数与临时锁定。 */
@RestController
@RequestMapping("/api/auth")
public class AuthController {

    private final UserDirectory userDirectory;
    private final TokenService tokenService;
    private final SessionService sessionService;
    private final RateLimiter rateLimiter;
    private final AuditLog auditLog;

    public AuthController(UserDirectory userDirectory, TokenService tokenService,
                          SessionService sessionService, RateLimiter rateLimiter,
                          AuditLog auditLog) {
        this.userDirectory = userDirectory;
        this.tokenService = tokenService;
        this.sessionService = sessionService;
        this.rateLimiter = rateLimiter;
        this.auditLog = auditLog;
    }

    public record LoginRequest(String username, String password) {
    }

    public record RefreshRequest(String token) {
    }

    @PostMapping("/token")
    public ResponseEntity<Map<String, Object>> loginWithToken(@RequestBody LoginRequest request) {
        return login(request, true);
    }

    @PostMapping("/session")
    public ResponseEntity<Map<String, Object>> loginWithSession(@RequestBody LoginRequest request) {
        return login(request, false);
    }

    @PostMapping("/refresh")
    public ResponseEntity<Map<String, Object>> refresh(@RequestBody RefreshRequest request) {
        try {
            TokenService.TokenPair pair = tokenService.refresh(request.token());
            Map<String, Object> body = new LinkedHashMap<>();
            body.put("token", pair.access().serialized());
            body.put("refreshToken", pair.refresh().serialized());
            body.put("expiresAt", pair.access().expiresAt().toString());
            return ResponseEntity.ok(body);
        } catch (CredentialException e) {
            return error(HttpStatus.UNAUTHORIZED, e.reason());
        }
    }

    private ResponseEntity<Map<String, Object>> login(LoginRequest request, boolean tokenEntry) {
        String key = "login:" + request.username();
        RateLimitResult pre = rateLimiter.check(key);
        if (pre.locked()) {
            audit(request.username(), DenyReason.LOCKED, "login blocked until " + pre.lockedUntil());
            return error(HttpStatus.TOO_MANY_REQUESTS, DenyReason.LOCKED);
        }
        if (!pre.permitted()) {
            audit(request.username(), DenyReason.RATE_LIMITED, "login rate limited");
            return error(HttpStatus.TOO_MANY_REQUESTS, DenyReason.RATE_LIMITED);
        }
        Optional<Subject> subject = userDirectory.verify(request.username(), request.password());
        if (subject.isEmpty()) {
            RateLimitResult post = rateLimiter.recordFailure(key);
            DenyReason reason = post.locked() ? DenyReason.LOCKED : DenyReason.UNAUTHENTICATED;
            audit(request.username(), reason, "bad credentials");
            return error(post.locked() ? HttpStatus.TOO_MANY_REQUESTS : HttpStatus.UNAUTHORIZED, reason);
        }
        rateLimiter.reset(key);
        Subject s = subject.get();
        audit(s.userId(), null, "login success via " + (tokenEntry ? "TOKEN" : "SESSION"));
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("userId", s.userId());
        body.put("tenantId", s.tenantId());
        if (tokenEntry) {
            TokenService.TokenPair pair = tokenService.issuePair(s.userId(), s.tenantId());
            body.put("token", pair.access().serialized());
            body.put("refreshToken", pair.refresh().serialized());
            body.put("expiresAt", pair.access().expiresAt().toString());
        } else {
            body.put("sessionId", sessionService.createSession(s.userId(), s.tenantId()));
        }
        return ResponseEntity.ok(body);
    }

    private void audit(String subject, DenyReason reason, String basis) {
        auditLog.record(new AuditEvent(Instant.now(), subject, "-", "-", null,
                reason == null, reason, basis));
    }

    static ResponseEntity<Map<String, Object>> error(HttpStatus status, DenyReason reason) {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("error", status.name());
        body.put("reason", reason.name());
        return ResponseEntity.status(status).body(body);
    }
}
