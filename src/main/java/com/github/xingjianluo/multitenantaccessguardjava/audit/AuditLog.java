package com.github.xingjianluo.multitenantaccessguardjava.audit;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;

/** 审计日志：打印到日志并保留内存副本供测试断言。 */
@Component
public class AuditLog {

    private static final Logger log = LoggerFactory.getLogger(AuditLog.class);

    private final List<AuditEvent> events = new CopyOnWriteArrayList<>();

    public void record(AuditEvent event) {
        events.add(event);
        log.info("AUDIT subject={} tenant={} resource={} action={} decision={} reason={} basis={}",
                event.subject(), event.tenant(), event.resource(), event.action(),
                event.allowed() ? "ALLOW" : "DENY",
                event.denyReason() == null ? "-" : event.denyReason(),
                event.basis());
    }

    public List<AuditEvent> events() {
        return List.copyOf(events);
    }
}
