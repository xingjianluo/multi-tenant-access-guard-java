package com.github.xingjianluo.multitenantaccessguardjava.audit;

import java.util.List;

/**
 * Audit sink. Records are appended (recent events retained in memory for tests) and
 * also printed to the application log in a single structured line.
 */
public interface AuditService {

    void record(AuditEvent event);

    List<AuditEvent> recent();

    List<AuditEvent> findBySubject(String tenantId, String subjectId);
}
