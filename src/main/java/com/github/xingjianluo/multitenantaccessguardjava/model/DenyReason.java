package com.github.xingjianluo.multitenantaccessguardjava.model;

/**
 * Distinguishable deny reasons. The name of the constant is the externally visible
 * reason code so that callers (and tests) can tell cross-tenant, missing-resource,
 * expired/tampered/replayed credential and lock cases apart.
 */
public enum DenyReason {
    /** Target resource does not exist (never revealed across tenant boundaries). */
    RESOURCE_NOT_FOUND,
    /** Subject and resource belong to different tenants. */
    CROSS_TENANT_ACCESS,
    /** No matching role/ownership permission for the action. */
    FORBIDDEN,
    /** No credential supplied or scheme unsupported. */
    UNAUTHENTICATED,
    /** Credential signature/format invalid, i.e. tampered. */
    INVALID_CREDENTIAL,
    /** Credential past its expiry time. */
    CREDENTIAL_EXPIRED,
    /** Credential was already consumed (replay), its family has been revoked. */
    CREDENTIAL_REPLAYED,
    /** Credential's token family has been revoked (e.g. detected replay). */
    CREDENTIAL_REVOKED,
    /** Username/password or SSO assertion could not be verified. */
    BAD_CREDENTIALS,
    /** Unknown login entry point requested. */
    UNSUPPORTED_ENTRY,
    /** Too many failed logins: account is temporarily locked. */
    ACCOUNT_LOCKED,
    /** Sensitive action rate limit exceeded: temporarily locked out. */
    RATE_LIMITED
}
