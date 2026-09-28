package com.github.highcumontoa.tokenrotationaccesscontroljava.web;

public record AuthenticatedUser(String username, String sessionId, String tokenId) {

    public static final String REQUEST_ATTRIBUTE = "authenticatedUser";
}
