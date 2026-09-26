package com.github.xingjianluo.multitenantaccessguardjava.policy;

import com.github.xingjianluo.multitenantaccessguardjava.domain.Action;
import com.github.xingjianluo.multitenantaccessguardjava.domain.GuardedResource;
import com.github.xingjianluo.multitenantaccessguardjava.domain.Role;

import java.util.Map;
import java.util.Optional;
import java.util.Set;

/**
 * 不可变权限快照：角色-动作授权表 + 资源注册表。
 * 判定始终基于某一个完整快照，保证一致性语义：
 * 一次请求要么看到完整旧配置，要么看到完整新配置，绝不出现中间态。
 */
public final class PolicySnapshot {

    private final long version;
    private final Map<Role, Set<Action>> rolePermissions;
    private final Map<String, GuardedResource> resources;

    public PolicySnapshot(long version,
                          Map<Role, Set<Action>> rolePermissions,
                          Map<String, GuardedResource> resources) {
        this.version = version;
        this.rolePermissions = Map.copyOf(rolePermissions);
        this.resources = Map.copyOf(resources);
    }

    public long version() {
        return version;
    }

    public Map<Role, Set<Action>> rolePermissions() {
        return rolePermissions;
    }

    public Map<String, GuardedResource> resources() {
        return resources;
    }

    public boolean roleAllows(Role role, Action action) {
        Set<Action> actions = rolePermissions.get(role);
        return actions != null && actions.contains(action);
    }

    public Optional<GuardedResource> findResource(String resourceId) {
        return Optional.ofNullable(resources.get(resourceId));
    }
}
