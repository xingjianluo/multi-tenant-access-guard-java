package com.github.xingjianluo.multitenantaccessguardjava.audit;

import com.github.xingjianluo.multitenantaccessguardjava.domain.Action;
import com.github.xingjianluo.multitenantaccessguardjava.domain.DenyReason;

import java.time.Instant;

/** 可追溯审计记录：主体、租户、资源、动作与判定依据。 */
public record AuditEvent(Instant at, String subject, String tenant, String resource,
                         Action action, boolean allowed, DenyReason denyReason, String basis) {
}
