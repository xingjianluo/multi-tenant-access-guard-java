package com.github.xingjianluo.multitenantaccessguardjava.auth;

/**
 * Server-side refresh-token state. Every mutation is atomic so that concurrent
 * presentations of the same refresh token can never both succeed (rotation with
 * replay detection and family revocation).
 */
public interface RefreshStore {

    /** Persist a freshly issued refresh token. */
    void save(RefreshRecord record);

    /**
     * Atomically mark {@code tokenId} consumed and register {@code nextTokenId} as the
     * live token of the family. Returns the verdict distinguishing first-use from
     * replay / revoked-family / unknown.
     */
    RefreshVerdict consume(String tokenId, String nextTokenId, long nowMillis);

    /** Look up the current live record of a family (for post-revocation inspection). */
    RefreshRecord findByFamily(String familyId);
}
