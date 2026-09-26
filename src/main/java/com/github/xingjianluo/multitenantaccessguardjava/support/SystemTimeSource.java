package com.github.xingjianluo.multitenantaccessguardjava.support;

import org.springframework.stereotype.Component;

/** Default wall-clock time source. */
@Component
public class SystemTimeSource implements TimeSource {
    @Override
    public long nowMillis() {
        return System.currentTimeMillis();
    }
}
