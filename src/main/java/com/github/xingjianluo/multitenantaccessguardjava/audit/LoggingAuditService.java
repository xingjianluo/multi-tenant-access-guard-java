package com.github.xingjianluo.multitenantaccessguardjava.audit;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.concurrent.ConcurrentLinkedDeque;
import java.util.stream.Collectors;

/**
 * Audit sink that prints one structured line per event and retains a bounded number of
 * recent events in memory for test inspection.
 *
 * <p>Every line carries subject, tenant, resource, action and the decision basis so
 * that a denial is traceable and explainable.
 */
@Service
public class LoggingAuditService implements AuditService {

    private static final Logger log = LoggerFactory.getLogger("AUDIT");
    private static final int MAX_RETAINED = 2_000;

    private final ConcurrentLinkedDeque<AuditEvent> events = new ConcurrentLinkedDeque<>();

    @Override
    public void record(AuditEvent event) {
        events.addLast(event);
        while (events.size() > MAX_RETAINED) {
            events.pollFirst();
        }
        log.info("AUDIT|type={}|tenant={}|subject={}|entry={}|resource={}|action={}|allowed={}|reason={}|basis={}|snapshot={}|trace={}",
                event.eventType(),
                event.tenantId(),
                event.subjectId(),
                event.loginEntry(),
                event.resourceId(),
                event.action(),
                event.allowed(),
                event.reason(),
                event.basis(),
                event.snapshotVersion(),
                event.traceId());
    }

    @Override
    public List<AuditEvent> recent() {
        return List.copyOf(events);
    }

    @Override
    public List<AuditEvent> findBySubject(String tenantId, String subjectId) {
        return events.stream()
                .filter(e -> tenantId.equals(e.tenantId()) && subjectId.equals(e.subjectId()))
                .collect(Collectors.toList());
    }
}
