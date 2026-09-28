package com.github.highcumontoa.tokenrotationaccesscontroljava.store;

import com.github.highcumontoa.tokenrotationaccesscontroljava.model.AuditEvent;

import java.util.List;

public interface AuditService {

    AuditEvent record(String action, String subject, String credentialId,
                      String outcome, String reason, String detail);

    List<AuditEvent> findAll();

    List<AuditEvent> findBySubject(String subject);
}
