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
 * 资源以 (tenantId, resourceId) 复合键登记：同一资源编号可在不同租户下各自独立存在，
 * 后写入的同名资源不会顶掉其他租户的记录。
 */
public final class PolicySnapshot {

    /** 资源复合键：租户 + 资源编号。 */
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

    /**
     * 只按调用方租户查找：其他租户的同名资源对调用方不可见，
     * 与资源不存在返回同样的空结果，不泄露对方是否持有该编号。
     */
    public Optional<GuardedResource> findResource(String tenantId, String resourceId) {
        return Optional.ofNullable(resources.get(new ResourceKey(tenantId, resourceId)));
    }
}
