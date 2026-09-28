package com.github.highcumontoa.tokenrotationaccesscontroljava.model;

import java.util.LinkedHashSet;
import java.util.Set;

public record SessionInfo(
        String sessionId,
        String username,
        String currentRefreshTokenHash,
        String currentAccessKeyId,
        Set<String> usedRefreshTokenHashes,
        long createdAtEpochMilli,
        long refreshCount,
        boolean revoked,
        String revokeReason) {

    public SessionInfo rotated(String newRefreshTokenHash, String newAccessKeyId) {
        Set<String> history = new LinkedHashSet<>(usedRefreshTokenHashes);
        history.add(currentRefreshTokenHash);
        return new SessionInfo(sessionId, username, newRefreshTokenHash, newAccessKeyId,
                Set.copyOf(history), createdAtEpochMilli, refreshCount + 1, false, null);
    }

    public SessionInfo revoked(String reason) {
        return new SessionInfo(sessionId, username, currentRefreshTokenHash, currentAccessKeyId,
                usedRefreshTokenHashes, createdAtEpochMilli, refreshCount, true, reason);
    }
}
