package com.github.xingjianluo.multitenantaccessguardjava.authz;

import com.github.xingjianluo.multitenantaccessguardjava.audit.AuditEvent;
import com.github.xingjianluo.multitenantaccessguardjava.audit.AuditService;
import com.github.xingjianluo.multitenantaccessguardjava.auth.CredentialService;
import com.github.xingjianluo.multitenantaccessguardjava.model.Action;
import com.github.xingjianluo.multitenantaccessguardjava.model.Decision;
import com.github.xingjianluo.multitenantaccessguardjava.model.DenyReason;
import com.github.xingjianluo.multitenantaccessguardjava.model.Permission;
import com.github.xingjianluo.multitenantaccessguardjava.model.PermissionSnapshot;
import com.github.xingjianluo.multitenantaccessguardjava.model.Resource;
import com.github.xingjianluo.multitenantaccessguardjava.model.Scope;
import com.github.xingjianluo.multitenantaccessguardjava.model.Subject;
import com.github.xingjianluo.multitenantaccessguardjava.support.TimeSource;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.function.Predicate;

/**
 * Role- and ownership-based authorization with explainable decisions.
 *
 * <p>Evaluation order (each branch yields a distinct, audited reason):
 * <ol>
 *   <li>the resource must exist inside the requested tenant, else
 *       {@link DenyReason#RESOURCE_NOT_FOUND};</li>
 *   <li>the subject's tenant must equal the resource tenant, else
 *       {@link DenyReason#CROSS_TENANT_ACCESS} (existence is checked tenant-scoped
 *       first, so a cross-tenant probe never confirms a foreign resource id);</li>
 *   <li>ownership or a matching RESOURCE/TENANT role permission must grant the action,
 *       else {@link DenyReason#FORBIDDEN}.</li>
 * </ol>
 *
 * <p>The entire evaluation reads one immutable {@link PermissionSnapshot}; the snapshot
 * version is embedded in the decision and audit row, making the effective rule
 * version explicit.
 */
@Service
public class DefaultAuthorizationService implements AuthorizationService {

    /** Role -> actions it grants, in increasing power. */
    private static final Map<String, Set<Action>> ROLE_ACTIONS = Map.of(
            "viewer", Set.of(Action.READ),
            "editor", Set.of(Action.READ, Action.WRITE),
            "admin", Set.of(Action.READ, Action.WRITE, Action.DELETE));

    private final PermissionStore permissionStore;
    private final CredentialService credentialService;
    private final AuditService auditService;
    private final TimeSource timeSource;

    public DefaultAuthorizationService(PermissionStore permissionStore,
                                       CredentialService credentialService,
                                       AuditService auditService,
                                       TimeSource timeSource) {
        this.permissionStore = permissionStore;
        this.credentialService = credentialService;
        this.auditService = auditService;
        this.timeSource = timeSource;
    }

    @Override
    public Decision authorize(Subject subject, String tenantId, String resourceId, Action action) {
        PermissionSnapshot snapshot = permissionStore.current();
        long version = snapshot.version();
        Decision decision = evaluate(subject, tenantId, resourceId, action, snapshot);
        audit(subject, tenantId, resourceId, action, decision);
        return decision;
    }

    private Decision evaluate(Subject subject, String tenantId, String resourceId,
                              Action action, PermissionSnapshot snapshot) {
        // 1) resource must exist within the tenant the caller is asking in
        Resource resource = permissionStore.findResource(tenantId, resourceId);
        if (resource == null) {
            return Decision.deny(DenyReason.RESOURCE_NOT_FOUND,
                    "no resource '" + resourceId + "' in tenant '" + tenantId + "'", snapshot.version());
        }

        // 2) hard tenant boundary
        if (!subject.tenantId().equals(resource.tenantId())) {
            return Decision.deny(DenyReason.CROSS_TENANT_ACCESS,
                    "subject tenant '" + subject.tenantId() + "' != resource tenant '"
                            + resource.tenantId() + "'", snapshot.version());
        }

        // 3a) ownership grants full control of the owned resource
        if (subject.subjectId().equals(resource.ownerSubjectId())) {
            return Decision.allow("owner of resource '" + resourceId + "'", snapshot.version());
        }

        // 3b) explicit resource-scoped grant
        for (Permission p : snapshot.permissions()) {
            if (matches(p, subject, resourceId)
                    && p.scope() == Scope.RESOURCE
                    && roleAllows(p.role(), action)) {
                return Decision.allow("role '" + p.role() + "' granted on resource '"
                        + resourceId + "'", snapshot.version());
            }
        }

        // 3c) tenant-wide grant
        for (Permission p : snapshot.permissions()) {
            if (matches(p, subject, resourceId)
                    && p.scope() == Scope.TENANT
                    && roleAllows(p.role(), action)) {
                return Decision.allow("role '" + p.role() + "' granted tenant-wide in '"
                        + tenantId + "'", snapshot.version());
            }
        }

        List<String> roles = credentialService.rolesOf(subject.tenantId(), subject.subjectId());
        return Decision.deny(DenyReason.FORBIDDEN,
                "subject '" + subject.subjectId() + "' roles " + roles
                        + " do not grant " + action + " on '" + resourceId + "'",
                snapshot.version());
    }

    private boolean matches(Permission p, Subject subject, String resourceId) {
        return p.tenantId().equals(subject.tenantId())
                && p.subjectId().equals(subject.subjectId())
                && (p.scope() == Scope.TENANT || resourceId.equals(p.resourceId()));
    }

    private boolean roleAllows(String role, Action action) {
        return ROLE_ACTIONS.getOrDefault(role, Set.of()).contains(action);
    }

    private void audit(Subject subject, String tenantId, String resourceId,
                       Action action, Decision decision) {
        Predicate<DenyReason> crossOrMissing =
                r -> r == DenyReason.RESOURCE_NOT_FOUND || r == DenyReason.CROSS_TENANT_ACCESS;
        String auditTenant = (decision.reason() != null && crossOrMissing.test(decision.reason()))
                ? tenantId : subject.tenantId();
        auditService.record(new AuditEvent(
                timeSource.nowMillis(),
                "AUTHZ",
                auditTenant,
                subject.subjectId(),
                subject.loginEntry() == null ? null : subject.loginEntry().name(),
                resourceId,
                action.name(),
                decision.allowed(),
                decision.reason() == null ? "ALLOW" : decision.reason().name(),
                decision.basis(),
                decision.snapshotVersion(),
                UUID.randomUUID().toString()));
    }
}
