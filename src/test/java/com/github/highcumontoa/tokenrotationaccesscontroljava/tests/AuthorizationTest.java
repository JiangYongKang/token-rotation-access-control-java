package com.github.highcumontoa.tokenrotationaccesscontroljava.tests;

import com.fasterxml.jackson.databind.JsonNode;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

/**
 * Covers the three distinguishable denials plus the granted case:
 * no token -> 401 MISSING_TOKEN; viewer calling write endpoint -> 403 ACCESS_DENIED;
 * bad credentials at login -> 401 LOGIN_FAILED.
 */
class AuthorizationTest extends AbstractApiTest {

    @Test
    void grantsReaderAndDistinguishesDenyReasons() {
        // 1) Unauthenticated
        ResponseEntity<String> noToken = get("/api/docs", null);
        assertEquals(HttpStatus.UNAUTHORIZED, noToken.getStatusCode());
        JsonNode noTokenErr = json(noToken.getBody());
        assertEquals("MISSING_TOKEN", noTokenErr.get("reason").asText());
        System.out.println("[DENY-1] no token -> status=" + noToken.getStatusCode()
                + " reason=" + noTokenErr.get("reason").asText()
                + " detail=" + noTokenErr.get("detail").asText());

        // 2) Bad login
        ResponseEntity<String> badLogin = post("/api/auth/login",
                "{\"username\":\"viewer\",\"password\":\"wrong\"}", null);
        assertEquals(HttpStatus.UNAUTHORIZED, badLogin.getStatusCode());
        JsonNode badLoginErr = json(badLogin.getBody());
        assertEquals("LOGIN_FAILED", badLoginErr.get("reason").asText());
        System.out.println("[DENY-2] bad password -> status=" + badLogin.getStatusCode()
                + " reason=" + badLoginErr.get("reason").asText());

        // 3) Authenticated, granted
        LoginBundle viewer = login("viewer", "viewer-pass");
        ResponseEntity<String> ok = get("/api/docs", viewer.accessToken());
        assertEquals(HttpStatus.OK, ok.getStatusCode());
        JsonNode okBody = json(ok.getBody());
        assertEquals("viewer", okBody.get("principal").asText());
        System.out.println("[GRANT] viewer GET /api/docs -> 200 accessTokenId="
                + viewer.accessTokenId() + " session=" + viewer.sessionId());

        // 4) Authenticated but lacking permission
        ResponseEntity<String> forbidden = get("/api/docs/write-demo", viewer.accessToken());
        assertEquals(HttpStatus.FORBIDDEN, forbidden.getStatusCode());
        JsonNode forbiddenErr = json(forbidden.getBody());
        assertEquals("ACCESS_DENIED", forbiddenErr.get("reason").asText());
        assertNotNull(forbiddenErr.get("credentialId").asText());
        System.out.println("[DENY-3] viewer GET /api/docs/write-demo -> status="
                + forbidden.getStatusCode() + " reason=" + forbiddenErr.get("reason").asText()
                + " credentialId=" + forbiddenErr.get("credentialId").asText()
                + " detail=" + forbiddenErr.get("detail").asText());

        // 5) Malformed / garbage token
        ResponseEntity<String> malformed = get("/api/docs", "not-a-real-token");
        assertEquals(HttpStatus.UNAUTHORIZED, malformed.getStatusCode());
        assertEquals("MALFORMED_TOKEN", json(malformed.getBody()).get("reason").asText());
        System.out.println("[DENY-4] garbage token -> reason="
                + json(malformed.getBody()).get("reason").asText());

        // 6) Editor can write
        LoginBundle editor = login("editor", "editor-pass");
        assertEquals(HttpStatus.OK, get("/api/docs/write-demo", editor.accessToken()).getStatusCode());
        System.out.println("[GRANT] editor GET /api/docs/write-demo -> 200 accessTokenId="
                + editor.accessTokenId());
    }
}
