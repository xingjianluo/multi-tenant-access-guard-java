package com.github.xingjianluo.multitenantaccessguardjava.auth;

import com.github.xingjianluo.multitenantaccessguardjava.model.LoginEntry;

/**
 * Stateless HMAC-signed compact token service (no external JWT library needed).
 * Verification distinguishes a tampered credential from an expired one.
 */
public interface TokenService {

    IssuedToken issueAccess(String tenantId, String subjectId, LoginEntry entry, String familyId, long nowMillis);

    IssuedToken issueRefresh(String tenantId, String subjectId, LoginEntry entry, String familyId, long nowMillis);

    /**
     * Verify signature and structure only (not expiry).
     *
     * @throws com.github.xingjianluo.multitenantaccessguardjava.support.AccessGuardException
     *         with reason INVALID_CREDENTIAL if the credential was tampered with
     */
    TokenPayload verifySignature(String serialized);

    long accessTtlMillis();

    long refreshTtlMillis();
}
