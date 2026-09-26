package com.github.xingjianluo.multitenantaccessguardjava.config;

import com.github.xingjianluo.multitenantaccessguardjava.auth.DefaultCredentialService;
import com.github.xingjianluo.multitenantaccessguardjava.authz.PermissionStore;
import com.github.xingjianluo.multitenantaccessguardjava.model.Permission;
import com.github.xingjianluo.multitenantaccessguardjava.model.Resource;
import com.github.xingjianluo.multitenantaccessguardjava.model.Scope;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.stereotype.Component;

import java.util.List;

/**
 * Seeds demo data:
 *
 * <pre>
 * tenant-a: alice (owner/editor), bob (viewer on one resource)
 * tenant-b: carol
 * resources: tenant-a/doc-1 (alice), tenant-a/doc-2 (alice), tenant-b/doc-1 (carol)
 * </pre>
 *
 * Both a password account and SSO federation can be used for alice/carol; SSO
 * assertions are minted on demand by the credential service.
 */
@Component
public class DataInitializer implements ApplicationRunner {

    private static final Logger log = LoggerFactory.getLogger(DataInitializer.class);

    private final PermissionStore permissionStore;
    private final DefaultCredentialService credentialService;

    public DataInitializer(PermissionStore permissionStore,
                           DefaultCredentialService credentialService) {
        this.permissionStore = permissionStore;
        this.credentialService = credentialService;
    }

    @Override
    public void run(ApplicationArguments args) {
        // credentials (tenant, username, subjectId, password, initial roles)
        credentialService.registerPasswordAccount("tenant-a", "alice", "alice", "alice-pw", List.of("editor"));
        credentialService.registerPasswordAccount("tenant-a", "bob", "bob", "bob-pw", List.of("viewer"));
        credentialService.registerPasswordAccount("tenant-b", "carol", "carol", "carol-pw", List.of("editor"));

        // resources
        permissionStore.addResource(new Resource("tenant-a", "doc-1", "alice"));
        permissionStore.addResource(new Resource("tenant-a", "doc-2", "alice"));
        permissionStore.addResource(new Resource("tenant-b", "doc-1", "carol"));

        // v1 permission snapshot: bob may only read doc-1; everything else is ownership/role driven
        permissionStore.replacePermissions(List.of(
                new Permission("tenant-a", "bob", "viewer", Scope.RESOURCE, "doc-1"),
                new Permission("tenant-a", "alice", "admin", Scope.TENANT, null),
                new Permission("tenant-b", "carol", "admin", Scope.TENANT, null)));

        log.info("seed data installed: tenants tenant-a/tenant-b, subjects alice/bob/carol, "
                + "snapshot v{}", permissionStore.current().version());
    }
}
