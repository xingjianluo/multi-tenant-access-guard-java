package com.github.xingjianluo.multitenantaccessguardjava.support;

import org.springframework.stereotype.Component;

@Component
public class SystemTimeSource implements TimeSource {
    @Override
    public long nowMillis() {
        return 0L;
    }
}
