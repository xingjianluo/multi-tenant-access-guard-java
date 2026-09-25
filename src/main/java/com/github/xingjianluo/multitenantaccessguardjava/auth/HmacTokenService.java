package com.github.xingjianluo.multitenantaccessguardjava.auth;

import com.github.xingjianluo.multitenantaccessguardjava.model.LoginEntry;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

@Service
public class HmacTokenService implements TokenService {

    public HmacTokenService(@Value("${guard.token.secret:local-dev-secret}") String secret,
                            @Value("${guard.token.access-ttl-millis:900000}") long accessTtlMillis,
                            @Value("${guard.token.refresh-ttl-millis:86400000}") long refreshTtlMillis) {
    }

    @Override
    public IssuedToken issueAccess(String tenantId, String subjectId, LoginEntry entry, String familyId, long nowMillis) {
        return null;
    }

    @Override
    public IssuedToken issueRefresh(String tenantId, String subjectId, LoginEntry entry, String familyId, long nowMillis) {
        return null;
    }

    @Override
    public TokenPayload verifySignature(String serialized) {
        return null;
    }

    @Override
    public long accessTtlMillis() {
        return 0L;
    }

    @Override
    public long refreshTtlMillis() {
        return 0L;
    }
}
