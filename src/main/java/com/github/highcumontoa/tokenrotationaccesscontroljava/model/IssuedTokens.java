package com.github.highcumontoa.tokenrotationaccesscontroljava.model;

public record IssuedTokens(
        String accessToken,
        String refreshToken,
        String sessionId,
        String accessTokenId,
        String refreshTokenId,
        long accessTokenTtlSeconds,
        long refreshTokenTtlSeconds) {
}
