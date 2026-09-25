package com.github.xingjianluo.multitenantaccessguardjava.auth;

import com.github.xingjianluo.multitenantaccessguardjava.model.LoginEntry;

/**
 * Identity claims carried by a token. Deliberately carries NO roles: roles are read
 * from the current permission snapshot at decision time, so a permission change takes
 * effect without waiting for outstanding tokens to expire.
 */
public record TokenPayload(String tenantId,
                           String subjectId,
                           LoginEntry loginEntry,
                           String tokenId,
                           String familyId,
                           long issuedAt,
                           long expiresAt,
                           String type) {

    public static final String TYPE_ACCESS = "access";
    public static final String TYPE_REFRESH = "refresh";
}
