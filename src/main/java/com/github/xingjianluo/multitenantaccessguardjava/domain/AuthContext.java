package com.github.xingjianluo.multitenantaccessguardjava.domain;

/** 任一登录入口认证成功后统一生成的认证上下文，后续判定只依赖它。 */
public record AuthContext(Subject subject, EntryType entryType, String credentialId) {
}
