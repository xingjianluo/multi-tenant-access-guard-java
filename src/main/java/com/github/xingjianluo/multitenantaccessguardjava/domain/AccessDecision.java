package com.github.xingjianluo.multitenantaccessguardjava.domain;

/** 访问判定结果：允许，或携带可区分拒绝原因的拒绝。 */
public record AccessDecision(boolean allowed, DenyReason denyReason, String detail) {

    public static AccessDecision allow() {
        return new AccessDecision(true, null, "allowed");
    }

    public static AccessDecision deny(DenyReason reason, String detail) {
        return new AccessDecision(false, reason, detail);
    }
}
