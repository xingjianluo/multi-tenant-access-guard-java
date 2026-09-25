package com.github.xingjianluo.multitenantaccessguardjava.support;

/** Abstraction over the clock so that expiry/lock tests can advance time deterministically. */
public interface TimeSource {
    long nowMillis();
}
