package com.github.xingjianluo.multitenantaccessguardjava.config;

import com.github.xingjianluo.multitenantaccessguardjava.ratelimit.RateLimitPolicy;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/** Wires named rate-limit policies. */
@Configuration
public class GuardConfig {

    @Bean("loginPolicy")
    public RateLimitPolicy loginPolicy(@Value("${guard.login.max-failures:5}") int maxFailures,
                                       @Value("${guard.login.window-millis:300000}") long windowMillis,
                                       @Value("${guard.login.lock-millis:600000}") long lockMillis) {
        return new RateLimitPolicy(maxFailures, windowMillis, lockMillis);
    }

    @Bean("sensitivePolicy")
    public RateLimitPolicy sensitivePolicy(@Value("${guard.sensitive.max-failures:3}") int maxFailures,
                                           @Value("${guard.sensitive.window-millis:60000}") long windowMillis,
                                           @Value("${guard.sensitive.lock-millis:120000}") long lockMillis) {
        return new RateLimitPolicy(maxFailures, windowMillis, lockMillis);
    }
}
