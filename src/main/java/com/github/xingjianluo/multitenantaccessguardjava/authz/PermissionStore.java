package com.github.xingjianluo.multitenantaccessguardjava.authz;

import com.github.xingjianluo.multitenantaccessguardjava.model.Permission;
import com.github.xingjianluo.multitenantaccessguardjava.model.PermissionSnapshot;
import com.github.xingjianluo.multitenantaccessguardjava.model.Resource;

import java.util.List;

/**
 * In-memory, concurrency-safe store for resources and the versioned permission
 * configuration. Permission updates are published as one immutable snapshot via an
 * atomic swap (monotonic version), which defines the cross-request consistency
 * semantics: never long-lived stale permissions, never a mixed/amplified read.
 */
public interface PermissionStore {

    Resource findResource(String tenantId, String resourceId);

    void addResource(Resource resource);

    PermissionSnapshot current();

    /** Atomically install a new immutable permission snapshot with a new version. */
    void replacePermissions(List<Permission> permissions);
}
