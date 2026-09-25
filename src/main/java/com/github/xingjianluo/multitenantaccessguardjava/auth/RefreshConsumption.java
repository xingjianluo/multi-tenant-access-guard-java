package com.github.xingjianluo.multitenantaccessguardjava.auth;

/**
 * The atomic state transition applied when a refresh token is presented:
 * the record is marked used / family revoked and the next token id is known.
 */
public record RefreshConsumption(RefreshRecord previous, String nextTokenId) {
}
