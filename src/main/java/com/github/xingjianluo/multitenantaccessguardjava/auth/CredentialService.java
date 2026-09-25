package com.github.xingjianluo.multitenantaccessguardjava.auth;

import com.github.xingjianluo.multitenantaccessguardjava.model.LoginEntry;
import com.github.xingjianluo.multitenantaccessguardjava.model.Subject;

/**
 * Directory + verification for the two login entry points and for subject roles.
 * Both entries ultimately resolve the same (tenantId, subjectId) {@link Subject}.
 */
public interface CredentialService {

    /**
     * Verify a password login.
     *
     * @throws com.github.xingjianluo.multitenantaccessguardjava.support.AccessGuardException BAD_CREDENTIALS
     */
    Subject verifyPassword(String tenantId, String username, String password);

    /**
     * Verify a single-use SSO assertion. Re-presenting the same assertion is a replay
     * and is rejected (and audited) rather than issuing a second session.
     *
     * @throws com.github.xingjianluo.multitenantaccessguardjava.support.AccessGuardException
     *         BAD_CREDENTIALS or CREDENTIAL_REPLAYED
     */
    Subject verifySsoAssertion(String assertionId);

    /** Mint a single-use SSO assertion for a subject (test/demo federation stub). */
    String issueSsoAssertion(String tenantId, String subjectId);

    java.util.List<String> rolesOf(String tenantId, String subjectId);

    void grantRole(String tenantId, String subjectId, String role);

    void revokeRole(String tenantId, String subjectId, String role);

    LoginEntry entryOf(String tenantId, String subjectId);
}
