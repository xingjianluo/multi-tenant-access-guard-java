package com.github.xingjianluo.multitenantaccessguardjava.tests;

import com.github.xingjianluo.multitenantaccessguardjava.support.TimeSource;

import java.util.concurrent.atomic.AtomicLong;

/** Deterministic clock shared by all beans in a test, advanced manually. */
public class MutableClock implements TimeSource {

    private final AtomicLong now;

    public MutableClock(long startMillis) {
        this.now = new AtomicLong(startMillis);
    }

    public static MutableClock startAt(long millis) {
        return new MutableClock(millis);
    }

    @Override
    public long nowMillis() {
        return now.get();
    }

    public void advance(long deltaMillis) {
        now.addAndGet(deltaMillis);
    }

    public void set(long millis) {
        now.set(millis);
    }
}
