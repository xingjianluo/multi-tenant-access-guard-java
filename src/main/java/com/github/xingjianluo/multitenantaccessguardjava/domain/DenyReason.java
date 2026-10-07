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
    /** 账号因连续登录失败被临时锁定。 */
    LOCKED,
    /** 敏感操作因连续失败被临时锁定（区别于限流与登录锁定）。 */
    SENSITIVE_LOCKED,
    /** 普通访问凭据不具备续期用途，不能用于续期。 */
    CREDENTIAL_NOT_REFRESHABLE,
    /** 凭据用途与入口不匹配（如续期凭据被当成访问凭据提交到业务入口）。 */
    CREDENTIAL_TYPE_MISMATCH
}
