package com.github.xingjianluo.multitenantaccessguardjava.policy;

import com.github.xingjianluo.multitenantaccessguardjava.audit.AuditEvent;
import com.github.xingjianluo.multitenantaccessguardjava.audit.AuditLog;
import com.github.xingjianluo.multitenantaccessguardjava.domain.AccessDecision;
import com.github.xingjianluo.multitenantaccessguardjava.domain.Action;
import com.github.xingjianluo.multitenantaccessguardjava.domain.AuthContext;
import com.github.xingjianluo.multitenantaccessguardjava.domain.DenyReason;
import com.github.xingjianluo.multitenantaccessguardjava.domain.GuardedResource;
import com.github.xingjianluo.multitenantaccessguardjava.domain.Role;
import org.springframework.stereotype.Component;

import java.time.Instant;

/**
 * 基于角色与资源归属的统一判定器，两种登录入口共用，保证结论一致。
 * 判定顺序固定，拒绝原因可区分：
 * 资源在本租户命名空间不存在 → 角色权限不足 → 非归属者。
 *
 * 租户隔离语义：资源查找以（主体租户, 资源编号）为键，主体只能看到本租户命名空间。
 * 跨租户访问他人同名资源时，本租户查不到该编号，统一返回 RESOURCE_NOT_FOUND——
 * 调用方无法据响应判断其他租户到底有没有这个资源（防探测）。
 * 若该编号在别的租户确实存在，审计 basis 中保留 CROSS_TENANT 标记供内部溯源。
 * 单次判定复用同一快照，结果可解释并写入审计。
 */
@Component
public class AccessEvaluator {

    private final PolicyStore policyStore;
    private final AuditLog auditLog;

    public AccessEvaluator(PolicyStore policyStore, AuditLog auditLog) {
        this.policyStore = policyStore;
        this.auditLog = auditLog;
    }

    public AccessDecision evaluate(AuthContext context, String resourceId, Action action) {
        PolicySnapshot snapshot = policyStore.current();
        AccessDecision decision = doEvaluate(snapshot, context, resourceId, action);
        auditLog.record(new AuditEvent(
                Instant.now(),
                context.subject().userId(),
                context.subject().tenantId(),
                resourceId,
                action,
                decision.allowed(),
                decision.denyReason(),
                "policyVersion=" + snapshot.version()
                        + ", entry=" + context.entryType()
                        + ", basis=" + decision.detail()));
        return decision;
    }

    private AccessDecision doEvaluate(PolicySnapshot snapshot, AuthContext context,
                                      String resourceId, Action action) {
        String subjectTenant = context.subject().tenantId();
        // 只在主体自己的租户命名空间内查找：跨租户同名资源对本主体不可见。
        GuardedResource resource = snapshot.findResource(subjectTenant, resourceId).orElse(null);
        if (resource == null) {
            // 内部审计确认是否为跨租户探测：其他租户有同编号资源时标记 CROSS_TENANT，
            // 但对调用方一律返回 RESOURCE_NOT_FOUND，不泄露存在性。
            boolean existsElsewhere = snapshot.resources().values().stream()
                    .anyMatch(r -> r.resourceId().equals(resourceId)
                            && !r.tenantId().equals(subjectTenant));
            String basis = existsElsewhere
                    ? "resource " + resourceId + " exists in another tenant (CROSS_TENANT), "
                            + "not visible to tenant " + subjectTenant
                    : "resource " + resourceId + " not found in tenant " + subjectTenant;
            return AccessDecision.deny(DenyReason.RESOURCE_NOT_FOUND, basis);
        }
        boolean roleAllowed = context.subject().roles().stream()
                .anyMatch(role -> snapshot.roleAllows(role, action));
        if (!roleAllowed) {
            return AccessDecision.deny(DenyReason.INSUFFICIENT_ROLE,
                    "roles " + context.subject().roles() + " cannot " + action);
        }
        // 写/删操作要求归属者本人，或本租户 ADMIN 代管。
        if (action != Action.READ
                && !resource.ownerId().equals(context.subject().userId())
                && !context.subject().roles().contains(Role.ADMIN)) {
            return AccessDecision.deny(DenyReason.NOT_OWNER,
                    "resource owned by " + resource.ownerId()
                            + ", subject " + context.subject().userId() + " is not owner or admin");
        }
        return AccessDecision.allow();
    }
}
