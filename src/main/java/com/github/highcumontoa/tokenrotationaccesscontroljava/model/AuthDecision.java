package com.github.highcumontoa.tokenrotationaccesscontroljava.model;

import java.util.List;

public sealed interface AuthDecision {

    record Granted(String username, List<Role> roles, String sessionId, String tokenId)
            implements AuthDecision {
    }

    record Denied(DenyReason reason, String detail, String tokenId) implements AuthDecision {
    }

    default boolean granted() {
        return this instanceof Granted;
    }
}
