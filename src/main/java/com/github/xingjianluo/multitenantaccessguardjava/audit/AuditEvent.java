package com.github.xingjianluo.multitenantaccessguardjava.audit;

/**
 * One traceable security event: authentication, authorization decision, rate-limit
 * lock or internal error. Designed so that logs always carry subject, tenant,
 * resource, action and the basis/reason of the decision.
 */
public record AuditEvent(long timestamp,
                         String eventType,
                         String tenantId,
                         String subjectId,
                         String loginEntry,
                         String resourceId,
                         String action,
                         boolean allowed,
                         String reason,
                         String basis,
                         Long snapshotVersion,
                         String traceId) {
}
