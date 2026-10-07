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

import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** 业务场景：同编号资源在不同租户下各自独立存在与隔离访问。 */
class TenantResourceIsolationTest {

    private static final Logger log = LoggerFactory.getLogger(TenantResourceIsolationTest.class);

    private InMemoryPolicyStore store;
    private AccessEvaluator evaluator;

    @BeforeEach
    void setUp() {
        store = new InMemoryPolicyStore();
        evaluator = new AccessEvaluator(store, new AuditLog());
    }

    private AuthContext ctx(String user, String tenant, Role... roles) {
        return new AuthContext(new Subject(user, tenant, Set.of(roles)), EntryType.TOKEN, "cred-1");
    }

    private void print(AccessDecision d, String user, String tenant, String resource) {
        log.info("TEST-TENANT subject={} tenant={} resource={} allowed={} reason={}",
                user, tenant, resource, d.allowed(), d.denyReason());
    }

    @Test
    void sameResourceIdCoexistsAcrossTenants() {
        // 两个租户各有一个同名资源 doc-shared，归属各自属主
        store.registerResource(new GuardedResource("doc-shared", "tenant-a", "u-alice"));
        store.registerResource(new GuardedResource("doc-shared", "tenant-b", "u-bob"));

        // 各自访问自己的那份都正常通过
        AccessDecision a = evaluator.evaluate(ctx("u-alice", "tenant-a", Role.USER),
                "doc-shared", Action.WRITE);
        print(a, "u-alice", "tenant-a", "doc-shared");
        assertTrue(a.allowed(), "tenant-a 主体访问本租户同名资源应通过");

        AccessDecision b = evaluator.evaluate(ctx("u-bob", "tenant-b", Role.USER),
                "doc-shared", Action.WRITE);
        print(b, "u-bob", "tenant-b", "doc-shared");
        assertTrue(b.allowed(), "tenant-b 主体访问本租户同名资源应通过");

        // 两份记录各自独立：移除 tenant-a 的不影响 tenant-b 的
        store.removeResource("tenant-a", "doc-shared");
        assertTrue(evaluator.evaluate(ctx("u-bob", "tenant-b", Role.USER),
                "doc-shared", Action.READ).allowed(), "移除他租户同名资源不得影响本租户记录");
    }

    @Test
    void crossTenantProbeIsIndistinguishableFromMissing() {
        store.registerResource(new GuardedResource("doc-shared", "tenant-a", "u-alice"));
        // tenant-b 并没有 doc-shared：跨租户探测与访问不存在资源的结论必须一致
        AccessDecision probe = evaluator.evaluate(ctx("u-bob", "tenant-b", Role.USER),
                "doc-shared", Action.READ);
        AccessDecision missing = evaluator.evaluate(ctx("u-bob", "tenant-b", Role.USER),
                "doc-never-existed", Action.READ);
        print(probe, "u-bob", "tenant-b", "doc-shared");
        print(missing, "u-bob", "tenant-b", "doc-never-existed");
        assertFalse(probe.allowed());
        assertEquals(DenyReason.RESOURCE_NOT_FOUND, probe.denyReason());
        assertEquals(probe.denyReason(), missing.denyReason(),
                "跨租户探测不得泄露对方是否持有该编号");
    }

    @Test
    void batchWritesAcrossTenantsDoNotEvictEachOther() {
        // 模拟租户数量与资源量上涨后的批量写入
        int tenants = 20, resourcesPerTenant = 50;
        for (int t = 0; t < tenants; t++) {
            for (int r = 0; r < resourcesPerTenant; r++) {
                store.registerResource(new GuardedResource(
                        "res-" + r, "tenant-" + t, "owner-" + t));
            }
        }
        // 每个租户的资源记录都还在，后写的没有顶掉先写的
        for (int t = 0; t < tenants; t++) {
            for (int r = 0; r < resourcesPerTenant; r++) {
                int tenant = t, resource = r;
                GuardedResource found = store.current()
                        .findResource("tenant-" + tenant, "res-" + resource).orElse(null);
                assertTrue(found != null && found.ownerId().equals("owner-" + tenant),
                        "tenant-" + tenant + " 的 res-" + resource + " 记录必须稳定存在");
            }
        }
        // 同名资源编号 res-0 在每个租户下各自独立
        assertEquals("owner-3", store.current().findResource("tenant-3", "res-0").orElseThrow().ownerId());
        assertEquals("owner-17", store.current().findResource("tenant-17", "res-0").orElseThrow().ownerId());
        log.info("TEST-TENANT batchWrite tenants={} resourcesPerTenant={} total={} allStable=true",
                tenants, resourcesPerTenant, tenants * resourcesPerTenant);
    }
}
