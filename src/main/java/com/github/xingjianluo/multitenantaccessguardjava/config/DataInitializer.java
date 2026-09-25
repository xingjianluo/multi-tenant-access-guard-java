package com.github.xingjianluo.multitenantaccessguardjava.config;

import com.github.xingjianluo.multitenantaccessguardjava.auth.CredentialService;
import com.github.xingjianluo.multitenantaccessguardjava.authz.PermissionStore;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.stereotype.Component;

/** Seeds demo tenants, credentials, resources and the v1 permission snapshot. */
@Component
public class DataInitializer implements ApplicationRunner {

    public DataInitializer(PermissionStore permissionStore, CredentialService credentialService) {
    }

    @Override
    public void run(ApplicationArguments args) {
    }
}
