package com.github.highcumontoa.tokenrotationaccesscontroljava.store;

import com.github.highcumontoa.tokenrotationaccesscontroljava.model.AuditEvent;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.time.Instant;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicLong;

@Component
public class InMemoryAuditService implements AuditService {

    private static final Logger log = LoggerFactory.getLogger(InMemoryAuditService.class);

    private final CopyOnWriteArrayList<AuditEvent> events = new CopyOnWriteArrayList<>();
    private final AtomicLong sequence = new AtomicLong();

    @Override
    public AuditEvent record(String action, String subject, String credentialId,
                             String outcome, String reason, String detail) {
        AuditEvent event = new AuditEvent(sequence.incrementAndGet(), Instant.now(),
                action, subject, credentialId, outcome, reason, detail);
        events.add(event);
        log.info("AUDIT seq={} action={} subject={} credentialId={} outcome={} reason={} detail={}",
                event.sequence(), action, subject, credentialId, outcome, reason, detail);
        return event;
    }

    @Override
    public List<AuditEvent> findAll() {
        return List.copyOf(events);
    }

    @Override
    public List<AuditEvent> findBySubject(String subject) {
        return events.stream().filter(e -> subject.equals(e.subject())).toList();
    }
}
