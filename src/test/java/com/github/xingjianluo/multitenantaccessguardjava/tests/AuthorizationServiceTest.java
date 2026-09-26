package com.github.xingjianluo.multitenantaccessguardjava.tests;

import com.github.xingjianluo.multitenantaccessguardjava.audit.LoggingAuditService;
import com.github.xingjianluo.multitenantaccessguardjava.auth.DefaultCredentialService;
import com.github.xingjianluo.multitenantaccessguardjava.authz.DefaultAuthorizationService;
import com.github.xingjianluo.multitenantaccessguardjava.authz.InMemoryPermissionStore;
import com.github.xingjianluo.multitenantaccessguardjava.model.Action;
import com.github.xingjianluo.multitenantaccessguardjava.model.Decision;
import com.github.xingjianluo.multitenantaccessguardjava.model.DenyReason;
import com.github.xingjianluo.multitenantaccessguardjava.model.LoginEntry;
import com.github.xingjianluo.multitenantaccessguardjava.model.Permission;
import com.github.xingjianluo.multitenantaccessguardjava.model.Resource;
import com.github.xingjianluo.multitenantaccessguardjava.model.Scope;
import com.github.xingjianluo.multitenantaccessguardjava.model.Subject;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class AuthorizationServiceTest {

    private static final Logger log = LoggerFactory.getLogger(AuthorizationServiceTest.class);

    private InMemoryPermissionStore store;
    private DefaultAuthorizationService authz;
    private LoggingAuditService audit;

    @BeforeEach
    void setUp() {
        store = new InMemoryPermissionStore();
        DefaultCredentialService creds = new DefaultCredentialService();
        audit = new LoggingAuditService();
        authz = new DefaultAuthorizationService(store, creds, audit, MutableClock.startAt(1L));

        store.addResource(new Resource("tenant-a", "doc-1", "alice"));
        store.addResource(new Resource("tenant-a", "doc-2", "alice"));
        store.addResource(new Resource("tenant-b", "doc-1", "carol"));
        // v1: bob can only read doc-1 in tenant-a
        store.replacePermissions(List.of(
                new Permission("tenant-a", "bob", "viewer", Scope.RESOURCE, "doc-1")));
    }

    private void logDecision(Subject s, String resourceId, Action action, Decision d) {
        log.info("TEST|case=authz|tenant={}|subject={}|entry={}|resource={}|action={}|allowed={}|reason={}|basis={}|snapshot=v{}",
                s.tenantId(), s.subjectId(), s.loginEntry(), resourceId, action,
                d.allowed(), d.reason(), d.basis(), d.snapshotVersion());
    }

    @Test
    @DisplayName("资源所有者对自己的资源放行")
    void ownerAllowed() {
        Subject alice = new Subject("tenant-a", "alice", LoginEntry.PASSWORD);
        Decision d = authz.authorize(alice, "tenant-a", "doc-2", Action.DELETE);
        assertTrue(d.allowed());
        logDecision(alice, "doc-2", Action.DELETE, d);
    }

    @Test
    @DisplayName("跨租户访问被拒，原因=CROSS_TENANT_ACCESS")
    void crossTenantDenied() {
        Subject carol = new Subject("tenant-b", "carol", LoginEntry.PASSWORD);
        Decision d = authz.authorize(carol, "tenant-a", "doc-1", Action.READ);
        assertFalse(d.allowed());
        assertEquals(DenyReason.CROSS_TENANT_ACCESS, d.reason());
        logDecision(carol, "doc-1", Action.READ, d);
    }

    @Test
    @DisplayName("同租户但无权限的动作被拒，原因=FORBIDDEN")
    void horizontalUnauthorizedDenied() {
        Subject bob = new Subject("tenant-a", "bob", LoginEntry.PASSWORD);
        // viewer on doc-1 cannot write
        Decision write = authz.authorize(bob, "tenant-a", "doc-1", Action.WRITE);
        assertFalse(write.allowed());
        assertEquals(DenyReason.FORBIDDEN, write.reason());
        // and has no grant at all on doc-2
        Decision read2 = authz.authorize(bob, "tenant-a", "doc-2", Action.READ);
        assertEquals(DenyReason.FORBIDDEN, read2.reason());
        logDecision(bob, "doc-1", Action.WRITE, write);
    }

    @Test
    @DisplayName("不存在的资源被拒，原因=RESOURCE_NOT_FOUND；跨租户探测同名资源也不泄露存在性")
    void missingResourceDenied() {
        Subject bob = new Subject("tenant-a", "bob", LoginEntry.PASSWORD);
        Decision d = authz.authorize(bob, "tenant-a", "ghost", Action.READ);
        assertEquals(DenyReason.RESOURCE_NOT_FOUND, d.reason());

        // tenant-b has its own doc-1; asking tenant-a names from a tenant-b context is
        // cross-tenant, but asking a non-existent tenant-local id is NOT_FOUND
        Subject carol = new Subject("tenant-b", "carol", LoginEntry.SSO);
        Decision ghost = authz.authorize(carol, "tenant-b", "ghost", Action.READ);
        assertEquals(DenyReason.RESOURCE_NOT_FOUND, ghost.reason());
        logDecision(bob, "ghost", Action.READ, d);
    }

    @Test
    @DisplayName("权限快照原子切换：v1禁止->v2授予，版本号与结论一致；撤销立即生效")
    void snapshotSwapConsistency() {
        Subject bob = new Subject("tenant-a", "bob", LoginEntry.PASSWORD);

        Decision before = authz.authorize(bob, "tenant-a", "doc-2", Action.READ);
        assertFalse(before.allowed());
        assertEquals(DenyReason.FORBIDDEN, before.reason());
        assertEquals(1L, before.snapshotVersion());

        // atomic grant -> v2
        store.replacePermissions(List.of(
                new Permission("tenant-a", "bob", "viewer", Scope.RESOURCE, "doc-1"),
                new Permission("tenant-a", "bob", "viewer", Scope.RESOURCE, "doc-2")));
        Decision granted = authz.authorize(bob, "tenant-a", "doc-2", Action.READ);
        assertTrue(granted.allowed());
        assertEquals(2L, granted.snapshotVersion());

        // atomic revoke -> v3 must take effect immediately (no stale permission window)
        store.replacePermissions(List.of(
                new Permission("tenant-a", "bob", "viewer", Scope.RESOURCE, "doc-1")));
        Decision revoked = authz.authorize(bob, "tenant-a", "doc-2", Action.READ);
        assertFalse(revoked.allowed());
        assertEquals(DenyReason.FORBIDDEN, revoked.reason());
        assertEquals(3L, revoked.snapshotVersion());
        logDecision(bob, "doc-2", Action.READ, revoked);
    }

    @Test
    @DisplayName("租户级角色授权仅在本租户内生效")
    void tenantScopedRoleStaysInsideTenant() {
        store.replacePermissions(List.of(
                new Permission("tenant-a", "bob", "admin", Scope.TENANT, null)));
        Subject bob = new Subject("tenant-a", "bob", LoginEntry.SSO);
        assertTrue(authz.authorize(bob, "tenant-a", "doc-2", Action.DELETE).allowed());

        // tenant-wide in a must never bleed into tenant-b resource
        Decision cross = authz.authorize(bob, "tenant-b", "doc-1", Action.READ);
        assertEquals(DenyReason.CROSS_TENANT_ACCESS, cross.reason());
        logDecision(bob, "doc-1", Action.READ, cross);
    }
}
