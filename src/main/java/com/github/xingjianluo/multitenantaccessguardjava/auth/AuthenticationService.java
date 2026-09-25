package com.github.xingjianluo.multitenantaccessguardjava.auth;

/**
 * Facade over the two login entries, token issuance/verification and refresh-token
 * rotation. All credential failures surface distinguishable
 * {@link com.github.xingjianluo.multitenantaccessguardjava.support.AccessGuardException}
 * reasons.
 */
public interface AuthenticationService {

    TokenBundle login(String entry, String tenantId, String username, String password, String assertionId);

    /**
     * Rotate a refresh token. Concurrent renewal is serialized: only the first
     * presentation succeeds; a second (replay) revokes the family and is denied.
     */
    TokenBundle refresh(String refreshToken);

    /**
     * Authenticate an access token presented on a request.
     *
     * @throws com.github.xingjianluo.multitenantaccessguardjava.support.AccessGuardException
     *         UNAUTHENTICATED / INVALID_CREDENTIAL / CREDENTIAL_EXPIRED
     */
    com.github.xingjianluo.multitenantaccessguardjava.model.Subject authenticate(String authorizationHeader);
}
