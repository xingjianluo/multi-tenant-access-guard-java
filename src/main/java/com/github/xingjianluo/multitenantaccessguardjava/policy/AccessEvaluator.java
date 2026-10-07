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
 * 资源在本租户下不存在（含他租户同名资源，不泄露存在性）→ 角色权限不足 → 非归属者。
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
        // 只按主体租户查找：他租户的同名资源与不存在返回同一结论，
        // 调用方无法通过探测判断其他租户是否持有该编号。
        GuardedResource resource = snapshot
                .findResource(context.subject().tenantId(), resourceId).orElse(null);
        if (resource == null) {
            return AccessDecision.deny(DenyReason.RESOURCE_NOT_FOUND,
                    "resource " + resourceId + " not found in tenant "
                            + context.subject().tenantId());
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
