package com.github.highcumontoa.tokenrotationaccesscontroljava.web.dto;

public record TokenResponse(
        String accessToken,
        String refreshToken,
        String sessionId,
        String accessTokenId,
        String refreshTokenId,
        String tokenType,
        long accessTokenTtlSeconds,
        long refreshTokenTtlSeconds) {
}
