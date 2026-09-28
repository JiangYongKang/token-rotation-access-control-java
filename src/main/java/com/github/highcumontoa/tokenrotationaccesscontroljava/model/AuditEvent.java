package com.github.highcumontoa.tokenrotationaccesscontroljava.model;

import java.time.Instant;

public record AuditEvent(
        long sequence,
        Instant timestamp,
        String action,
        String subject,
        String credentialId,
        String outcome,
        String reason,
        String detail) {
}
