package com.github.xingjianluo.multitenantaccessguardjava.policy;

import com.github.xingjianluo.multitenantaccessguardjava.domain.Action;
import com.github.xingjianluo.multitenantaccessguardjava.domain.GuardedResource;
import com.github.xingjianluo.multitenantaccessguardjava.domain.Role;

import java.util.List;
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

    /** 注册单个资源；同编号资源在不同租户下各自独立、互不覆盖。 */
    void registerResource(GuardedResource resource);

    /** 批量注册：在一次原子快照替换内全部生效，适用于租户/资源量上涨后的批量写入。 */
    void registerResources(List<GuardedResource> resources);

    /** 删除某租户命名空间下的资源（不影响其他租户的同名资源）。 */
    void removeResource(String tenantId, String resourceId);
}
