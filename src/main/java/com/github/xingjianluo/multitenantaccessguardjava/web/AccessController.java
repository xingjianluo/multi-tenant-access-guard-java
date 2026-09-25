package com.github.xingjianluo.multitenantaccessguardjava.web;

import com.github.xingjianluo.multitenantaccessguardjava.audit.AuditService;
import com.github.xingjianluo.multitenantaccessguardjava.auth.AuthenticationService;
import com.github.xingjianluo.multitenantaccessguardjava.authz.AuthorizationService;
import com.github.xingjianluo.multitenantaccessguardjava.model.Action;
import com.github.xingjianluo.multitenantaccessguardjava.model.Subject;
import com.github.xingjianluo.multitenantaccessguardjava.ratelimit.RateLimitPolicy;
import com.github.xingjianluo.multitenantaccessguardjava.ratelimit.RateLimitService;
import com.github.xingjianluo.multitenantaccessguardjava.support.TimeSource;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/**
 * Resource access endpoints. Every request is authenticated (two entries converge on
 * the same Subject), then authorized against the current permission snapshot.
 * DELETE is additionally treated as a sensitive action and rate limited.
 */
@RestController
@RequestMapping("/api/tenants/{tenantId}/resources/{resourceId}")
public class AccessController {

    public AccessController(AuthenticationService authenticationService,
                            AuthorizationService authorizationService,
                            RateLimitService rateLimitService,
                            AuditService auditService,
                            TimeSource timeSource,
                            @Qualifier("sensitivePolicy") RateLimitPolicy sensitivePolicy) {
    }

    public record AccessResponse(boolean allowed, String tenantId, String subjectId,
                                 String resourceId, String action, String basis, long snapshotVersion) {
    }

    private AccessResponse doAccess(String authorizationHeader, String tenantId,
                                    String resourceId, Action action, boolean sensitive) {
        return null;
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
                                 @RequestParam(name = "simulateFailure", defaultValue = "false") boolean simulateFailure) {
        return doAccess(authorizationHeader, tenantId, resourceId, Action.DELETE, true);
    }

    static Subject unused() {
        return null;
    }
}
