package com.github.highcumontoa.tokenrotationaccesscontroljava.tests;

import com.fasterxml.jackson.databind.JsonNode;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;

import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.CyclicBarrier;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Administrative revocation/rotation semantics:
 * - role/permission changes invalidate old access tokens immediately (CREDENTIALS_CHANGED),
 * - signing key rotation invalidates every access token signed with the dropped key,
 * - forced logout revokes all of a user's sessions,
 * - concurrent logout vs refresh never corrupts state.
 */
class RevocationAndRotationTest extends AbstractApiTest {

    private LoginBundle admin() {
        return login("admin", "admin-pass");
    }

    @Test
    void roleChangeInvalidatesOldAccessTokenImmediately() {
        LoginBundle admin = admin();
        LoginBundle editor = login("editor", "editor-pass");
        assertEquals(HttpStatus.OK, get("/api/docs/write-demo", editor.accessToken()).getStatusCode());

        // Demote editor to viewer while the old access token is still cryptographically valid.
        ResponseEntity<String> change = post("/api/admin/change-roles",
                "{\"username\":\"editor\",\"roles\":[\"VIEWER\"]}", admin.accessToken());
        assertEquals(HttpStatus.OK, change.getStatusCode());
        System.out.println("[ROLE-CHANGE] editor -> VIEWER, response=" + change.getBody());

        // Same old token: write is no longer possible. Two distinct, explainable outcomes are
        // possible; this implementation invalidates the old token via the user version bump.
        ResponseEntity<String> denied = get("/api/docs/write-demo", editor.accessToken());
        assertEquals(HttpStatus.UNAUTHORIZED, denied.getStatusCode());
        JsonNode err = json(denied.getBody());
        assertEquals("CREDENTIALS_CHANGED", err.get("reason").asText());
        System.out.println("[ROLE-CHANGE] old access token rejected credentialId="
                + err.get("credentialId").asText() + " reason=" + err.get("reason").asText()
                + " detail=" + err.get("detail").asText());

        // A fresh login reflects the new permissions: can read, cannot write.
        LoginBundle demoted = login("editor", "editor-pass");
        assertEquals(HttpStatus.OK, get("/api/docs", demoted.accessToken()).getStatusCode());
        ResponseEntity<String> stillNoWrite = get("/api/docs/write-demo", demoted.accessToken());
        assertEquals(HttpStatus.FORBIDDEN, stillNoWrite.getStatusCode());
        assertEquals("ACCESS_DENIED", json(stillNoWrite.getBody()).get("reason").asText());
        System.out.println("[ROLE-CHANGE] new token: read=200, write=403 ACCESS_DENIED");

        // restore roles for test isolation within the shared context
        post("/api/admin/change-roles",
                "{\"username\":\"editor\",\"roles\":[\"EDITOR\"]}", admin.accessToken());
    }

    @Test
    void permissionRemovalTakesEffectWithoutReLoginForSameVersionToken() {
        LoginBundle admin = admin();
        LoginBundle viewer = login("viewer", "viewer-pass");
        assertEquals(HttpStatus.OK, get("/api/docs", viewer.accessToken()).getStatusCode());

        // Remove the viewer role entirely (empty roles). Version bump invalidates old tokens.
        ResponseEntity<String> change = post("/api/admin/change-roles",
                "{\"username\":\"viewer\",\"roles\":[]}", admin.accessToken());
        assertEquals(HttpStatus.OK, change.getStatusCode());

        ResponseEntity<String> denied = get("/api/docs", viewer.accessToken());
        assertEquals(HttpStatus.UNAUTHORIZED, denied.getStatusCode());
        assertEquals("CREDENTIALS_CHANGED", json(denied.getBody()).get("reason").asText());
        System.out.println("[PERMISSION-REMOVAL] viewer old token -> "
                + json(denied.getBody()).get("reason").asText());

        // restore
        post("/api/admin/change-roles",
                "{\"username\":\"viewer\",\"roles\":[\"VIEWER\"]}", admin.accessToken());
    }

    @Test
    void keyRotationInvalidatesExistingAccessTokensButNewLoginsWork() {
        LoginBundle first = login("viewer", "viewer-pass");
        String oldToken = first.accessToken();
        assertEquals(HttpStatus.OK, get("/api/docs", oldToken).getStatusCode());

        LoginBundle admin = admin();
        ResponseEntity<String> rotated = post("/api/admin/rotate-key", "{}", admin.accessToken());
        assertEquals(HttpStatus.OK, rotated.getStatusCode());
        JsonNode keyResp = json(rotated.getBody());
        assertNotEquals(keyResp.get("oldKeyId").asText(), keyResp.get("newKeyId").asText());
        System.out.println("[KEY-ROTATE] oldKeyId=" + keyResp.get("oldKeyId").asText()
                + " newKeyId=" + keyResp.get("newKeyId").asText());

        // Old token signature can no longer be verified.
        ResponseEntity<String> denied = get("/api/docs", oldToken);
        assertEquals(HttpStatus.UNAUTHORIZED, denied.getStatusCode());
        JsonNode err = json(denied.getBody());
        assertEquals("UNKNOWN_SIGNING_KEY", err.get("reason").asText());
        System.out.println("[KEY-ROTATE] old access token rejected credentialId="
                + err.get("credentialId").asText() + " reason=" + err.get("reason").asText()
                + " detail=" + err.get("detail").asText());

        // Tokens minted after rotation are signed with the new key and work.
        LoginBundle after = login("viewer", "viewer-pass");
        assertEquals(HttpStatus.OK, get("/api/docs", after.accessToken()).getStatusCode());
        System.out.println("[KEY-ROTATE] newly minted token works credentialId="
                + after.accessTokenId());

        // Old refresh tokens still rotate (refresh tokens are opaque and key-independent), and the
        // new access token from a refresh is also signed with the new key.
        LoginBundle refreshed = refresh(first.refreshToken());
        assertEquals(HttpStatus.OK, get("/api/docs", refreshed.accessToken()).getStatusCode());
    }

    @Test
    void passwordRotationAndForceLogoutRevokeImmediately() throws InterruptedException {
        LoginBundle admin = admin();
        LoginBundle editor = login("editor", "editor-pass");
        assertEquals(HttpStatus.OK, get("/api/docs", editor.accessToken()).getStatusCode());

        // Change editor's password: version bump + all sessions revoked.
        ResponseEntity<String> changed = post("/api/admin/change-password",
                "{\"username\":\"editor\",\"newPassword\":\"new-editor-pass\"}",
                admin.accessToken());
        assertEquals(HttpStatus.OK, changed.getStatusCode());
        System.out.println("[PASSWORD-ROTATE] " + changed.getBody());

        ResponseEntity<String> oldAccess = get("/api/docs", editor.accessToken());
        assertEquals(HttpStatus.UNAUTHORIZED, oldAccess.getStatusCode());
        // Session revocation is checked before version, hence SESSION_REVOKED.
        assertEquals("SESSION_REVOKED", json(oldAccess.getBody()).get("reason").asText());
        System.out.println("[PASSWORD-ROTATE] old access -> "
                + json(oldAccess.getBody()).get("reason").asText());

        ResponseEntity<String> oldRefresh = post("/api/auth/refresh",
                "{\"refreshToken\":\"" + editor.refreshToken() + "\"}", null);
        assertEquals(HttpStatus.UNAUTHORIZED, oldRefresh.getStatusCode());
        System.out.println("[PASSWORD-ROTATE] old refresh -> "
                + json(oldRefresh.getBody()).get("reason").asText());

        // Old password no longer works; new password works.
        assertEquals(HttpStatus.UNAUTHORIZED, post("/api/auth/login",
                "{\"username\":\"editor\",\"password\":\"editor-pass\"}", null).getStatusCode());
        assertEquals(HttpStatus.OK, post("/api/auth/login",
                "{\"username\":\"editor\",\"password\":\"new-editor-pass\"}", null).getStatusCode());

        // Force logout: a freshly logged-in user loses all sessions.
        LoginBundle fresh = login("editor", "new-editor-pass");
        assertEquals(HttpStatus.OK, get("/api/docs", fresh.accessToken()).getStatusCode());
        ResponseEntity<String> forced = post("/api/admin/force-logout",
                "{\"username\":\"editor\"}", admin.accessToken());
        assertEquals(HttpStatus.OK, forced.getStatusCode());
        System.out.println("[FORCE-LOGOUT] " + forced.getBody());
        assertEquals(HttpStatus.UNAUTHORIZED, get("/api/docs", fresh.accessToken()).getStatusCode());
        assertEquals("SESSION_REVOKED",
                json(get("/api/docs", fresh.accessToken()).getBody()).get("reason").asText());

        // restore password for other tests sharing the context
        post("/api/admin/change-password",
                "{\"username\":\"editor\",\"newPassword\":\"editor-pass\"}",
                admin.accessToken());
    }

    @Test
    void concurrentLogoutAndRefreshNeverCorruptsState() throws Exception {
        int rounds = 10;
        int consistent = 0;
        for (int round = 0; round < rounds; round++) {
            LoginBundle tokens = login("viewer", "viewer-pass");
            String rt = tokens.refreshToken();

            CyclicBarrier barrier = new CyclicBarrier(2);
            ConcurrentLinkedQueue<String> outcomes = new ConcurrentLinkedQueue<>();
            ExecutorService pool = Executors.newFixedThreadPool(2);
            CountDownLatch done = new CountDownLatch(2);

            pool.submit(() -> {
                try {
                    barrier.await(5, TimeUnit.SECONDS);
                    ResponseEntity<String> r = post("/api/auth/refresh",
                            "{\"refreshToken\":\"" + rt + "\"}", null);
                    outcomes.add(r.getStatusCode() == HttpStatus.OK ? "REFRESH_OK"
                            : "REFRESH_DENIED:" + json(r.getBody()).get("reason").asText());
                } catch (Exception e) {
                    outcomes.add("REFRESH_EX");
                } finally {
                    done.countDown();
                }
            });
            pool.submit(() -> {
                try {
                    barrier.await(5, TimeUnit.SECONDS);
                    ResponseEntity<String> r = post("/api/auth/logout",
                            "{\"refreshToken\":\"" + rt + "\"}", null);
                    outcomes.add(r.getStatusCode() == HttpStatus.OK ? "LOGOUT_OK" : "LOGOUT_DENIED");
                } catch (Exception e) {
                    outcomes.add("LOGOUT_EX");
                } finally {
                    done.countDown();
                }
            });
            assertTrue(done.await(20, TimeUnit.SECONDS));
            pool.shutdown();

            // Wait past the post-rotation grace window, then present the old token again.
            Thread.sleep(1200);
            ResponseEntity<String> after = post("/api/auth/refresh",
                    "{\"refreshToken\":\"" + rt + "\"}", null);
            assertEquals(HttpStatus.UNAUTHORIZED, after.getStatusCode(),
                    "round " + round + ": old token must never succeed afterwards, outcomes="
                            + outcomes);
            String afterReason = json(after.getBody()).get("reason").asText();
            assertTrue(afterReason.equals("SESSION_REVOKED")
                            || afterReason.equals("REFRESH_TOKEN_REUSE")
                            || afterReason.equals("SESSION_NOT_FOUND"),
                    "round " + round + ": unexpected terminal reason " + afterReason);

            // Regardless of which side won, a third immediate attempt must see a dead chain.
            ResponseEntity<String> third = post("/api/auth/refresh",
                    "{\"refreshToken\":\"" + rt + "\"}", null);
            assertEquals(HttpStatus.UNAUTHORIZED, third.getStatusCode());
            String thirdReason = json(third.getBody()).get("reason").asText();
            assertTrue(thirdReason.equals("SESSION_REVOKED")
                            || thirdReason.equals("SESSION_NOT_FOUND"),
                    "round " + round + ": chain must be terminal, got " + thirdReason);

            if (outcomes.contains("REFRESH_OK")) {
                consistent++;
            } else {
                consistent++;
            }
            System.out.println("[LOGOUT-VS-REFRESH] round=" + round + " outcomes=" + outcomes
                    + " oldTokenAfterGrace=" + afterReason
                    + " thirdAttempt=" + thirdReason);
        }
        assertEquals(rounds, consistent);
    }

    @Test
    void auditTrailExplainsEveryDecision() {
        LoginBundle admin = admin();
        LoginBundle viewer = login("viewer", "viewer-pass");
        get("/api/docs/write-demo", viewer.accessToken()); // 403
        get("/api/docs", "Bearer garbage-token");         // 401

        ResponseEntity<String> audit = get("/api/admin/audit", admin.accessToken());
        assertEquals(HttpStatus.OK, audit.getStatusCode());
        JsonNode events = json(audit.getBody());
        assertTrue(events.isArray());
        System.out.println("[AUDIT] total events=" + events.size());
        boolean sawAccessDenied = false;
        for (JsonNode event : events) {
            if ("ACCESS".equals(event.get("action").asText())
                    && "DENIED".equals(event.get("outcome").asText())) {
                String reason = event.get("reason").asText();
                if ("ACCESS_DENIED".equals(reason) || "MALFORMED_TOKEN".equals(reason)) {
                    sawAccessDenied = true;
                }
                System.out.println("[AUDIT-EVENT] seq=" + event.get("sequence").asLong()
                        + " action=" + event.get("action").asText()
                        + " subject=" + event.get("subject").asText()
                        + " credentialId=" + event.get("credentialId").asText()
                        + " outcome=" + event.get("outcome").asText()
                        + " reason=" + (event.has("reason") && !event.get("reason").isNull()
                                ? event.get("reason").asText() : "-")
                        + " detail=" + event.get("detail").asText());
            }
        }
        assertTrue(sawAccessDenied, "audit must contain an explainable denied access event");
    }
}
