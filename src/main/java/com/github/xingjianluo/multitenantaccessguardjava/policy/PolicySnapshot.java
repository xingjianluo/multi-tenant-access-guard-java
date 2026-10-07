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
 *
 * 资源以（租户, 资源编号）复合键唯一标识：同一个 resourceId 可以在不同租户下
 * 各自独立存在、独立管理归属，后注册的资源不会顶掉其他租户的同名资源。
 */
public final class PolicySnapshot {

    /** 资源的复合键：租户 + 资源编号，全局唯一。 */
    public record ResourceKey(String tenantId, String resourceId) {
    }

    private final long version;
    private final Map<Role, Set<Action>> rolePermissions;
    private final Map<ResourceKey, GuardedResource> resources;

    public PolicySnapshot(long version,
                          Map<Role, Set<Action>> rolePermissions,
                          Map<ResourceKey, GuardedResource> resources) {
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

    public Map<ResourceKey, GuardedResource> resources() {
        return resources;
    }

    public boolean roleAllows(Role role, Action action) {
        Set<Action> actions = rolePermissions.get(role);
        return actions != null && actions.contains(action);
    }

    /** 按租户与资源编号精确查找：只能看到本租户命名空间下的资源。 */
    public Optional<GuardedResource> findResource(String tenantId, String resourceId) {
        return Optional.ofNullable(resources.get(new ResourceKey(tenantId, resourceId)));
    }
}
