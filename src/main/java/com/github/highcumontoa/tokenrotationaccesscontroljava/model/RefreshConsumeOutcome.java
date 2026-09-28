package com.github.highcumontoa.tokenrotationaccesscontroljava.model;

public sealed interface RefreshConsumeOutcome {

    record Rotated(IssuedTokens tokens, SessionInfo session) implements RefreshConsumeOutcome {
    }

    record Rejected(DenyReason reason, String detail, String credentialId)
            implements RefreshConsumeOutcome {
    }

    record ReuseDetected(String sessionId, String presentedTokenId, String username)
            implements RefreshConsumeOutcome {
    }
}
