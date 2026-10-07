package com.github.xingjianluo.multitenantaccessguardjava.auth;

import java.time.Instant;

/** 已签发的令牌（值对象）。 */
public record AuthToken(String tokenId, String subjectUserId, String tenantId,
                        TokenType tokenType, String familyId,
                        Instant issuedAt, Instant expiresAt, String serialized) {

    /** 令牌类型：访问凭据 / 续期凭据，二者不可混用。 */
    public enum TokenType {
        /** 日常访问用凭据，不能用于续期。 */
        ACCESS,
        /** 专用于续期的凭据，不能用于访问。 */
        REFRESH
    }
}
