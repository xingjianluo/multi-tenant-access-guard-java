package com.github.xingjianluo.multitenantaccessguardjava.tests;

import com.github.xingjianluo.multitenantaccessguardjava.audit.AuditLog;
import com.github.xingjianluo.multitenantaccessguardjava.domain.AccessDecision;
import com.github.xingjianluo.multitenantaccessguardjava.domain.Action;
import com.github.xingjianluo.multitenantaccessguardjava.domain.AuthContext;
import com.github.xingjianluo.multitenantaccessguardjava.domain.DenyReason;
import com.github.xingjianluo.multitenantaccessguardjava.domain.EntryType;
import com.github.xingjianluo.multitenantaccessguardjava.domain.GuardedResource;
import com.github.xingjianluo.multitenantaccessguardjava.domain.Role;
import com.github.xingjianluo.multitenantaccessguardjava.domain.Subject;
import com.github.xingjianluo.multitenantaccessguardjava.policy.AccessEvaluator;
import com.github.xingjianluo.multitenantaccessguardjava.policy.InMemoryPolicyStore;
import com.github.xingjianluo.multitenantaccessguardjava.policy.PolicySnapshot;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class AccessEvaluatorTest {

    private static final Logger log = LoggerFactory.getLogger(AccessEvaluatorTest.class);

    private InMemoryPolicyStore store;
    private AuditLog auditLog;
    private AccessEvaluator evaluator;

    @BeforeEach
    void setUp() {
        store = new InMemoryPolicyStore();
        auditLog = new AuditLog();
        evaluator = new AccessEvaluator(store, auditLog);
        store.registerResource(new GuardedResource("doc-1", "tenant-a", "u-alice"));
        store.registerResource(new GuardedResource("doc-2", "tenant-b", "u-bob"));
    }

    private AuthContext ctx(String user, String tenant, Role... roles) {
        return new AuthContext(new Subject(user, tenant, Set.of(roles)), EntryType.TOKEN, "cred-1");
    }

    private void print(AccessDecision d, String user, String tenant, String resource, Action action) {
        log.info("TEST-DECISION subject={} tenant={} resource={} action={} allowed={} reason={} basis={}",
                user, tenant, resource, action, d.allowed(), d.denyReason(), d.detail());
    }

    @Test
    void ownerCanReadAndWrite() {
        AccessDecision d = evaluator.evaluate(ctx("u-alice", "tenant-a", Role.USER), "doc-1", Action.WRITE);
        print(d, "u-alice", "tenant-a", "doc-1", Action.WRITE);
        assertTrue(d.allowed());
    }

    @Test
    void crossTenantIsDeniedWithoutExistenceLeak() {
        AccessDecision d = evaluator.evaluate(ctx("u-bob", "tenant-b", Role.USER), "doc-1", Action.READ);
        print(d, "u-bob", "tenant-b", "doc-1", Action.READ);
        assertFalse(d.allowed());
        // 跨租户探测与资源不存在返回同一结论，不泄露对方是否持有该编号
        assertEquals(DenyReason.RESOURCE_NOT_FOUND, d.denyReason());
    }

    @Test
    void missingResourceIsDenied() {
        AccessDecision d = evaluator.evaluate(ctx("u-alice", "tenant-a", Role.ADMIN), "doc-x", Action.READ);
        print(d, "u-alice", "tenant-a", "doc-x", Action.READ);
        assertFalse(d.allowed());
        assertEquals(DenyReason.RESOURCE_NOT_FOUND, d.denyReason());
    }

    @Test
    void viewerCannotWrite() {
        AccessDecision d = evaluator.evaluate(ctx("u-dave", "tenant-a", Role.VIEWER), "doc-1", Action.WRITE);
        print(d, "u-dave", "tenant-a", "doc-1", Action.WRITE);
        assertFalse(d.allowed());
        assertEquals(DenyReason.INSUFFICIENT_ROLE, d.denyReason());
    }

    @Test
    void nonOwnerCannotDeleteButAdminCan() {
        store.grant(Role.USER, Action.DELETE); // 先放行角色权限，专测归属检查
        AccessDecision denied = evaluator.evaluate(ctx("u-dave", "tenant-a", Role.USER), "doc-1", Action.DELETE);
        print(denied, "u-dave", "tenant-a", "doc-1", Action.DELETE);
        assertEquals(DenyReason.NOT_OWNER, denied.denyReason());

        AccessDecision allowed = evaluator.evaluate(ctx("u-carol", "tenant-a", Role.ADMIN), "doc-1", Action.DELETE);
        print(allowed, "u-carol", "tenant-a", "doc-1", Action.DELETE);
        assertTrue(allowed.allowed());
    }

    @Test
    void policyChangeAppliesAtomicallyToNewEvaluations() {
        // 进行中的判定复用旧快照：旧快照内结论不变
        PolicySnapshot before = store.current();
        store.revoke(Role.USER, Action.WRITE);
        assertTrue(before.roleAllows(Role.USER, Action.WRITE));
        assertFalse(store.current().roleAllows(Role.USER, Action.WRITE));

        // 新判定立即按新快照拒绝，旧权限不残留
        AccessDecision d = evaluator.evaluate(ctx("u-alice", "tenant-a", Role.USER), "doc-1", Action.WRITE);
        print(d, "u-alice", "tenant-a", "doc-1", Action.WRITE);
        assertEquals(DenyReason.INSUFFICIENT_ROLE, d.denyReason());

        // 恢复授权同样整体生效，不出现中间态
        store.grant(Role.USER, Action.WRITE);
        assertTrue(evaluator.evaluate(ctx("u-alice", "tenant-a", Role.USER), "doc-1", Action.WRITE).allowed());
    }

    @Test
    void auditTrailContainsSubjectTenantResourceActionAndBasis() {
        evaluator.evaluate(ctx("u-bob", "tenant-b", Role.USER), "doc-1", Action.READ);
        assertEquals(1, auditLog.events().size());
        var event = auditLog.events().get(0);
        assertEquals("u-bob", event.subject());
        assertEquals("tenant-b", event.tenant());
        assertEquals("doc-1", event.resource());
        assertEquals(Action.READ, event.action());
        assertEquals(DenyReason.RESOURCE_NOT_FOUND, event.denyReason());
        assertTrue(event.basis().contains("policyVersion="));
    }
}
