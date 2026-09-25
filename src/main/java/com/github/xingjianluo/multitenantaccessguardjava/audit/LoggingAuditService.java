package com.github.xingjianluo.multitenantaccessguardjava.audit;

import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class LoggingAuditService implements AuditService {

    @Override
    public void record(AuditEvent event) {
    }

    @Override
    public List<AuditEvent> recent() {
        return List.of();
    }

    @Override
    public List<AuditEvent> findBySubject(String tenantId, String subjectId) {
        return List.of();
    }
}
