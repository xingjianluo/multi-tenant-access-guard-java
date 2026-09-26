package com.github.xingjianluo.multitenantaccessguardjava.domain;

import java.util.Set;

/** 访问主体：某租户下的一个用户及其角色集合。 */
public record Subject(String userId, String tenantId, Set<Role> roles) {
    public Subject {
        roles = roles == null ? Set.of() : Set.copyOf(roles);
    }
}
