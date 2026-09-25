package com.github.xingjianluo.multitenantaccessguardjava.authz;

import com.github.xingjianluo.multitenantaccessguardjava.audit.AuditService;
import com.github.xingjianluo.multitenantaccessguardjava.auth.CredentialService;
import com.github.xingjianluo.multitenantaccessguardjava.model.Action;
import com.github.xingjianluo.multitenantaccessguardjava.model.Decision;
import com.github.xingjianluo.multitenantaccessguardjava.model.Subject;
import com.github.xingjianluo.multitenantaccessguardjava.support.TimeSource;
import org.springframework.stereotype.Service;

@Service
public class DefaultAuthorizationService implements AuthorizationService {

    public DefaultAuthorizationService(PermissionStore permissionStore,
                                       CredentialService credentialService,
                                       AuditService auditService,
                                       TimeSource timeSource) {
    }

    @Override
    public Decision authorize(Subject subject, String tenantId, String resourceId, Action action) {
        return null;
    }
}
