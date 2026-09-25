package com.github.xingjianluo.multitenantaccessguardjava.auth;

import com.github.xingjianluo.multitenantaccessguardjava.audit.AuditService;
import com.github.xingjianluo.multitenantaccessguardjava.model.Subject;
import com.github.xingjianluo.multitenantaccessguardjava.ratelimit.RateLimitService;
import com.github.xingjianluo.multitenantaccessguardjava.support.TimeSource;
import org.springframework.stereotype.Service;

@Service
public class DefaultAuthenticationService implements AuthenticationService {

    public DefaultAuthenticationService(TokenService tokenService,
                                        RefreshStore refreshStore,
                                        CredentialService credentialService,
                                        RateLimitService rateLimitService,
                                        AuditService auditService,
                                        TimeSource timeSource) {
    }

    @Override
    public TokenBundle login(String entry, String tenantId, String username, String password, String assertionId) {
        return null;
    }

    @Override
    public TokenBundle refresh(String refreshToken) {
        return null;
    }

    @Override
    public Subject authenticate(String authorizationHeader) {
        return null;
    }
}
