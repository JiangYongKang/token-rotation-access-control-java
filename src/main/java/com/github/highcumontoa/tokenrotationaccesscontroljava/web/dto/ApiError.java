package com.github.highcumontoa.tokenrotationaccesscontroljava.web.dto;

public record ApiError(
        String error,
        String reason,
        String detail,
        String credentialId) {
}
