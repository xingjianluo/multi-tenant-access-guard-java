package com.github.xingjianluo.multitenantaccessguardjava.ratelimit;

import com.github.xingjianluo.multitenantaccessguardjava.audit.AuditService;
import com.github.xingjianluo.multitenantaccessguardjava.support.TimeSource;
import org.springframework.stereotype.Service;

@Service
public class FixedWindowRateLimitService implements RateLimitService {

    public FixedWindowRateLimitService(TimeSource timeSource, AuditService auditService) {
    }

    @Override
    public RateResult check(String key, long nowMillis) {
        return null;
    }

    @Override
    public RateResult penalize(String key, long nowMillis) {
        return null;
    }

    @Override
    public void reset(String key) {
    }
}
