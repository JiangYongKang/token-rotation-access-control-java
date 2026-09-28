package com.github.highcumontoa.tokenrotationaccesscontroljava.token;

import java.util.List;

public record Claims(
        String tokenId,
        String subject,
        String sessionId,
        long userVersion,
        List<String> roles,
        long issuedAtEpochMilli,
        long expiresAtEpochMilli) {
}
