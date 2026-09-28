package com.github.highcumontoa.tokenrotationaccesscontroljava.tests;

import com.fasterxml.jackson.databind.JsonNode;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;

import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * Uses a 1-second access-token lifetime so expiry can be verified locally.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT,
        properties = "app.security.access-token-ttl-seconds=1")
class ExpiredTokenTest extends AbstractApiTest {

    @Test
    void expiredAccessTokenIsRejectedWithDistinctReason() throws InterruptedException {
        LoginBundle tokens = login("viewer", "viewer-pass");
        assertEquals(HttpStatus.OK, get("/api/docs", tokens.accessToken()).getStatusCode());
        System.out.println("[EXPIRY] fresh token works credentialId=" + tokens.accessTokenId());

        Thread.sleep(1200);
        ResponseEntity<String> expired = get("/api/docs", tokens.accessToken());
        assertEquals(HttpStatus.UNAUTHORIZED, expired.getStatusCode());
        JsonNode err = json(expired.getBody());
        assertEquals("EXPIRED_TOKEN", err.get("reason").asText());
        System.out.println("[EXPIRY] expired token rejected credentialId="
                + err.get("credentialId").asText() + " reason=" + err.get("reason").asText()
                + " detail=" + err.get("detail").asText());

        // Refresh still yields a working new access token.
        LoginBundle renewed = refresh(tokens.refreshToken());
        assertEquals(HttpStatus.OK, get("/api/docs", renewed.accessToken()).getStatusCode());
        System.out.println("[EXPIRY] renewed access token works credentialId="
                + renewed.accessTokenId());
    }
}
