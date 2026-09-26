package com.github.xingjianluo.multitenantaccessguardjava.domain;

/** 可区分的拒绝原因。 */
public enum DenyReason {
    /** 未通过身份认证（未登录 / 凭据无效）。 */
    UNAUTHENTICATED,
    /** 凭据已过期。 */
    CREDENTIAL_EXPIRED,
    /** 凭据被篡改（签名不合法）。 */
    CREDENTIAL_TAMPERED,
    /** 凭据被重放。 */
    CREDENTIAL_REPLAYED,
    /** 资源不存在。 */
    RESOURCE_NOT_FOUND,
    /** 跨租户访问。 */
    CROSS_TENANT,
    /** 角色权限不足。 */
    INSUFFICIENT_ROLE,
    /** 非资源归属者，操作被拒绝。 */
    NOT_OWNER,
    /** 触发限流。 */
    RATE_LIMITED,
    /** 账号被临时锁定。 */
    LOCKED
}
