package com.github.xingjianluo.multitenantaccessguardjava.auth;

import java.time.Instant;

/** 已签发的令牌（值对象）。 */
public record AuthToken(String tokenId, String subjectUserId, String tenantId,
                        Instant issuedAt, Instant expiresAt, String serialized) {
}
