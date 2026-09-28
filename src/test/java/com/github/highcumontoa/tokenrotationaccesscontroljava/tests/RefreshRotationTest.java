package com.github.highcumontoa.tokenrotationaccesscontroljava.tests;

import com.fasterxml.jackson.databind.JsonNode;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;

/**
 * Serial rotation semantics:
 * - each refresh issues a brand new refresh token and invalidates the presented one;
 * - presenting the rotated-out (old) token is detected as reuse and revokes the whole chain;
 * - after reuse, even the newest token stops working (SESSION_REVOKED).
 */
class RefreshRotationTest extends AbstractApiTest {

    @Test
    void oneTimeRotationAndReuseDetection() throws InterruptedException {
        LoginBundle first = login("editor", "editor-pass");
        System.out.println("[ROTATE-0] login session=" + first.sessionId()
                + " rt1=" + first.refreshTokenId());

        // First rotation succeeds
        LoginBundle second = refresh(first.refreshToken());
        assertEquals(first.sessionId(), second.sessionId());
        assertNotEquals(first.refreshToken(), second.refreshToken());
        System.out.println("[ROTATE-1] oldRt=" + first.refreshTokenId()
                + " -> newRt=" + second.refreshTokenId());

        // Wait past the post-rotation grace window so the old token is a genuine replay rather
        // than a late straggler of a concurrent burst.
        Thread.sleep(1200);

        // Old refresh token reused after the grace window: reuse detected
        ResponseEntity<String> replay = post("/api/auth/refresh",
                "{\"refreshToken\":\"" + first.refreshToken() + "\"}", null);
        assertEquals(HttpStatus.UNAUTHORIZED, replay.getStatusCode());
        JsonNode replayErr = json(replay.getBody());
        assertEquals("REFRESH_TOKEN_REUSE", replayErr.get("reason").asText());
        System.out.println("[REUSE] replayed credential=" + replayErr.get("credentialId").asText()
                + " -> " + replayErr.get("reason").asText()
                + " detail=" + replayErr.get("detail").asText());

        // A token that was never valid / a third attempt with the same old token
        ResponseEntity<String> replayAgain = post("/api/auth/refresh",
                "{\"refreshToken\":\"" + first.refreshToken() + "\"}", null);
        assertEquals(HttpStatus.UNAUTHORIZED, replayAgain.getStatusCode());
        System.out.println("[REUSE-AGAIN] second presentation -> reason="
                + json(replayAgain.getBody()).get("reason").asText());

        // The whole chain is dead: even the newest refresh token is rejected
        ResponseEntity<String> newestFails = post("/api/auth/refresh",
                "{\"refreshToken\":\"" + second.refreshToken() + "\"}", null);
        assertEquals(HttpStatus.UNAUTHORIZED, newestFails.getStatusCode());
        JsonNode newestErr = json(newestFails.getBody());
        assertEquals("SESSION_REVOKED", newestErr.get("reason").asText());
        System.out.println("[CHAIN-DEAD] newest credential="
                + json(newestFails.getBody()).get("credentialId")
                + " rejected reason=" + newestErr.get("reason").asText()
                + " detail=" + newestErr.get("detail").asText());

        // Existing access tokens of the revoked session are rejected at resource access too
        ResponseEntity<String> accessFails = get("/api/docs", second.accessToken());
        assertEquals(HttpStatus.UNAUTHORIZED, accessFails.getStatusCode());
        assertEquals("SESSION_REVOKED", json(accessFails.getBody()).get("reason").asText());
        System.out.println("[CHAIN-DEAD] access token of revoked session -> "
                + json(accessFails.getBody()).get("reason").asText());

        // An unknown random refresh token
        ResponseEntity<String> unknown = post("/api/auth/refresh",
                "{\"refreshToken\":\"rt.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\"}", null);
        assertEquals(HttpStatus.UNAUTHORIZED, unknown.getStatusCode());
        assertEquals("SESSION_NOT_FOUND", json(unknown.getBody()).get("reason").asText());
        System.out.println("[UNKNOWN-RT] reason=" + json(unknown.getBody()).get("reason").asText());
    }

    @Test
    void multipleSequentialRotationsAllWork() {
        LoginBundle current = login("viewer", "viewer-pass");
        for (int i = 1; i <= 3; i++) {
            LoginBundle next = refresh(current.refreshToken());
            assertNotEquals(current.refreshToken(), next.refreshToken());
            System.out.println("[CHAIN-" + i + "] " + current.refreshTokenId()
                    + " -> " + next.refreshTokenId() + " sameSession="
                    + current.sessionId().equals(next.sessionId()));
            current = next;
        }
        // newest access token works
        assertEquals(HttpStatus.OK, get("/api/docs", current.accessToken()).getStatusCode());
    }
}
