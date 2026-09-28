package com.github.highcumontoa.tokenrotationaccesscontroljava.token;

import java.util.List;

public interface TokenService {

    IssuedAccess issueAccessToken(String username, List<String> roles, String sessionId, long userVersion);

    ParseResult parseAccessToken(String token);

    GeneratedSecret generateRefreshToken();

    String sha256Hash(String value);

    record IssuedAccess(String token, String tokenId) {
    }
}
