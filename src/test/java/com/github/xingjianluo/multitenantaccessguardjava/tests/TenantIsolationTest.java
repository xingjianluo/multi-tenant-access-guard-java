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
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 同编号资源的租户隔离：各自独立存在、跨租户防探测、批量写入不互相顶掉。
 */
class TenantIsolationTest {

    private static final Logger log = LoggerFactory.getLogger(TenantIsolationTest.class);

    private InMemoryPolicyStore store;
    private AccessEvaluator evaluator;
    private AuditLog auditLog;

    @BeforeEach
    void setUp() {
        store = new InMemoryPolicyStore();
        auditLog = new AuditLog();
        evaluator = new AccessEvaluator(store, auditLog);
        // 两个租户各自注册同名资源，归属不同属主
        store.registerResource(new GuardedResource("shared-doc", "tenant-a", "u-alice"));
        store.registerResource(new GuardedResource("shared-doc", "tenant-b", "u-bob"));
        // tenant-a 独占的资源：tenant-b 视角下应与“不存在”不可区分
        store.registerResource(new GuardedResource("doc-only-in-a", "tenant-a", "u-alice"));
    }

    private AuthContext ctx(String user, String tenant, Role... roles) {
        return new AuthContext(new Subject(user, tenant, Set.of(roles)), EntryType.TOKEN, "cred");
    }

    @Test
    void sameResourceIdExistsIndependentlyPerTenant() {
        AccessDecision a = evaluator.evaluate(
                ctx("u-alice", "tenant-a", Role.USER), "shared-doc", Action.WRITE);
        AccessDecision b = evaluator.evaluate(
                ctx("u-bob", "tenant-b", Role.USER), "shared-doc", Action.WRITE);
        log.info("TEST-TENANT-ISOLATION business=same-id-own-tenant a={} b={} result=PASS",
                a.allowed(), b.allowed());
        assertTrue(a.allowed(), "tenant-a 访问自己的 shared-doc 必须通过");
        assertTrue(b.allowed(), "tenant-b 访问自己的 shared-doc 必须通过");

        // 各租户看到的是各自那份（属主不同，互不覆盖）
        assertEquals("u-alice",
                store.current().findResource("tenant-a", "shared-doc").orElseThrow().ownerId());
        assertEquals("u-bob",
                store.current().findResource("tenant-b", "shared-doc").orElseThrow().ownerId());
    }

    @Test
    void crossTenantSameNameIsIndistinguishableFromMissing() {
        // 对方租户确实存在、但本租户不存在的编号：跨租户探测仍返回 RESOURCE_NOT_FOUND（防探测）
        AccessDecision probeExisting = evaluator.evaluate(
                ctx("u-bob", "tenant-b", Role.USER), "doc-only-in-a", Action.READ);
        // 双方都不存在的编号
        AccessDecision probeMissing = evaluator.evaluate(
                ctx("u-bob", "tenant-b", Role.USER), "no-such-doc", Action.READ);

        log.info("TEST-TENANT-ISOLATION business=anti-probe existingElsewhere reason={} | trulyMissing reason={}",
                probeExisting.denyReason(), probeMissing.denyReason());
        assertFalse(probeExisting.allowed());
        assertFalse(probeMissing.allowed());
        assertEquals(DenyReason.RESOURCE_NOT_FOUND, probeExisting.denyReason(),
                "跨租户碰别人的同名资源必须与“不存在”不可区分");
        assertEquals(DenyReason.RESOURCE_NOT_FOUND, probeMissing.denyReason());
        // 内部审计仍能区分并溯源
        assertTrue(probeExisting.detail().contains("CROSS_TENANT"));
        assertTrue(probeMissing.detail().contains("not found"));
    }

    @Test
    void batchWritesAcrossManyTenantsNeverOverwriteEachOther() {
        int tenantCount = 200;
        int perTenant = 50;
        List<GuardedResource> batch = new ArrayList<>();
        for (int t = 0; t < tenantCount; t++) {
            String tenant = "tenant-" + t;
            for (int r = 0; r < perTenant; r++) {
                // 大量租户使用完全相同的资源编号集合
                batch.add(new GuardedResource("res-" + r, tenant, "owner-" + t + "-" + r));
            }
        }
        store.registerResources(batch);

        // 每个租户的每份同名记录都还在，且归属正确（没有被后写顶掉）
        for (int t = 0; t < tenantCount; t++) {
            for (int r = 0; r < perTenant; r++) {
                GuardedResource found = store.current()
                        .findResource("tenant-" + t, "res-" + r).orElseThrow();
                assertEquals("owner-" + t + "-" + r, found.ownerId(),
                        "批量写入后租户 " + t + " 的记录不得丢失或被顶掉");
            }
        }
        // 原有两租户同名资源依旧完好
        assertEquals("u-alice",
                store.current().findResource("tenant-a", "shared-doc").orElseThrow().ownerId());
        assertEquals("u-bob",
                store.current().findResource("tenant-b", "shared-doc").orElseThrow().ownerId());

        // 抽查判定：tenant-199 访问自己的 res-0 通过，访问 tenant-0 的不可见
        assertTrue(evaluator.evaluate(
                ctx("owner-199-0", "tenant-199", Role.USER), "res-0", Action.WRITE).allowed());
        AccessDecision cross = evaluator.evaluate(
                ctx("owner-199-0", "tenant-199", Role.USER), "shared-doc", Action.READ);
        assertEquals(DenyReason.RESOURCE_NOT_FOUND, cross.denyReason());
        log.info("TEST-TENANT-ISOLATION business=bulk-no-overwrite tenants={} perTenant={} result=PASS",
                tenantCount, perTenant);
    }

    @Test
    void removeInOneTenantDoesNotAffectOtherTenant() {
        store.removeResource("tenant-a", "shared-doc");
        assertTrue(store.current().findResource("tenant-a", "shared-doc").isEmpty(),
                "本租户删除后应查不到");
        assertTrue(store.current().findResource("tenant-b", "shared-doc").isPresent(),
                "另一租户的同名资源不受影响");
        log.info("TEST-TENANT-ISOLATION business=scoped-remove result=PASS");
    }
}
