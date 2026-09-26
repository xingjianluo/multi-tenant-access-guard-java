package com.github.xingjianluo.multitenantaccessguardjava.policy;

import com.github.xingjianluo.multitenantaccessguardjava.domain.Action;
import com.github.xingjianluo.multitenantaccessguardjava.domain.GuardedResource;
import com.github.xingjianluo.multitenantaccessguardjava.domain.Role;

import java.util.Set;

/**
 * 权限配置存储：以原子替换快照的方式发布变更，
 * 保证进行中的请求看到完整旧快照或完整新快照，不出现中间态。
 */
public interface PolicyStore {

    /** 获取当前快照（单次判定应复用同一快照）。 */
    PolicySnapshot current();

    void grant(Role role, Action action);

    void revoke(Role role, Action action);

    void setRolePermissions(Role role, Set<Action> actions);

    void registerResource(GuardedResource resource);

    void removeResource(String resourceId);
}
