package com.github.xingjianluo.multitenantaccessguardjava.authz;

import com.github.xingjianluo.multitenantaccessguardjava.model.Permission;
import com.github.xingjianluo.multitenantaccessguardjava.model.PermissionSnapshot;
import com.github.xingjianluo.multitenantaccessguardjava.model.Resource;
import org.springframework.stereotype.Component;

import java.util.List;

@Component
public class InMemoryPermissionStore implements PermissionStore {

    @Override
    public Resource findResource(String tenantId, String resourceId) {
        return null;
    }

    @Override
    public void addResource(Resource resource) {
    }

    @Override
    public PermissionSnapshot current() {
        return null;
    }

    @Override
    public void replacePermissions(List<Permission> permissions) {
    }
}
