package com.github.highcumontoa.tokenrotationaccesscontroljava.tests;

import com.fasterxml.jackson.databind.JsonNode;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.CyclicBarrier;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * N threads present the SAME refresh token at the same instant. Exactly one rotation may succeed;
 * the others must fail, and no two successful refresh tokens may exist. A follow-up attempt with
 * the losers' perspective plus any successful new token confirms the chain state is consistent.
 */
class ConcurrentRefreshTest extends AbstractApiTest {

    private record Attempt(boolean success, String reason, String newRefreshToken,
                           String credentialId) {
    }

    @Test
    void concurrentRefreshOfSameTokenHasExactlyOneWinner() throws Exception {
        LoginBundle tokens = login("editor", "editor-pass");
        String sharedRefreshToken = tokens.refreshToken();

        int threads = 20;
        ExecutorService pool = Executors.newFixedThreadPool(threads);
        CyclicBarrier barrier = new CyclicBarrier(threads);
        CountDownLatch done = new CountDownLatch(threads);
        ConcurrentLinkedQueue<Attempt> attempts = new ConcurrentLinkedQueue<>();

        List<Future<?>> futures = new ArrayList<>();
        for (int i = 0; i < threads; i++) {
            futures.add(pool.submit(() -> {
                try {
                    barrier.await(5, TimeUnit.SECONDS);
                    ResponseEntity<String> resp = post("/api/auth/refresh",
                            "{\"refreshToken\":\"" + sharedRefreshToken + "\"}", null);
                    if (resp.getStatusCode() == HttpStatus.OK) {
                        LoginBundle bundle = parseBundle(resp.getBody());
                        attempts.add(new Attempt(true, "ROTATED",
                                bundle.refreshToken(), bundle.refreshTokenId()));
                    } else {
                        JsonNode err = json(resp.getBody());
                        attempts.add(new Attempt(false, err.get("reason").asText(),
                                null, err.has("credentialId") ? err.get("credentialId").asText() : "-"));
                    }
                } catch (Exception e) {
                    attempts.add(new Attempt(false, "EXCEPTION:" + e.getMessage(), null, "-"));
                } finally {
                    done.countDown();
                }
            }));
        }
        assertTrue(done.await(30, TimeUnit.SECONDS), "all refresh attempts must finish");
        for (Future<?> f : futures) {
            f.get(5, TimeUnit.SECONDS);
        }
        pool.shutdown();

        long winners = attempts.stream().filter(Attempt::success).count();
        List<Attempt> winnerList = attempts.stream().filter(Attempt::success).toList();
        List<Attempt> losers = attempts.stream().filter(a -> !a.success()).toList();

        System.out.println("[CONCURRENT-REFRESH] threads=" + threads + " winners=" + winners
                + " losers=" + losers.size());
        Set<String> winnerTokens = new HashSet<>();
        for (Attempt w : winnerList) {
            winnerTokens.add(w.newRefreshToken());
            System.out.println("[CONCURRENT-REFRESH] WINNER newCredential=" + w.credentialId());
        }
        losers.stream().collect(java.util.stream.Collectors.groupingBy(Attempt::reason))
                .forEach((reason, list) ->
                        System.out.println("[CONCURRENT-REFRESH] LOSER reason=" + reason
                                + " count=" + list.size()));

        assertEquals(1, winners, "exactly one concurrent refresh must succeed");
        assertEquals(1, winnerTokens.size(), "the single winner must produce one token");
        assertEquals(threads - 1, losers.size());
        assertTrue(losers.stream().allMatch(a -> "CONCURRENT_REFRESH_LOST".equals(a.reason())),
                "every loser must be a concurrency loser, not a reuse revocation: "
                        + losers.stream().map(Attempt::reason).toList());
        assertTrue(attempts.stream().noneMatch(a -> "REFRESH_TOKEN_REUSE".equals(a.reason())),
                "a same-instant concurrent race must never be misclassified as token reuse");

        // Consistency check: the winning token can be used exactly once more (another rotation),
        // proving the chain advanced exactly once overall. If any loser had also rotated, this
        // would fail because the winner's token would no longer be the current one.
        LoginBundle rotatedAgain = refresh(winnerList.get(0).newRefreshToken());
        System.out.println("[CONCURRENT-REFRESH] winner token usable afterwards -> newCredential="
                + rotatedAgain.refreshTokenId());
        assertEquals(HttpStatus.OK, get("/api/docs", rotatedAgain.accessToken()).getStatusCode());
    }

    @Test
    void concurrentRefreshOfUnknownTokenAllFail() throws Exception {
        int threads = 8;
        ExecutorService pool = Executors.newFixedThreadPool(threads);
        CyclicBarrier barrier = new CyclicBarrier(threads);
        ConcurrentLinkedQueue<String> reasons = new ConcurrentLinkedQueue<>();
        String unknown = "rt.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        for (int i = 0; i < threads; i++) {
            pool.submit(() -> {
                try {
                    barrier.await();
                    ResponseEntity<String> resp = post("/api/auth/refresh",
                            "{\"refreshToken\":\"" + unknown + "\"}", null);
                    reasons.add(json(resp.getBody()).get("reason").asText());
                } catch (Exception ignored) {
                    reasons.add("EXCEPTION");
                }
            });
        }
        pool.shutdown();
        assertTrue(pool.awaitTermination(20, TimeUnit.SECONDS));
        System.out.println("[CONCURRENT-UNKNOWN] outcomes=" + reasons);
        assertEquals(threads, reasons.size());
        assertTrue(reasons.stream().allMatch("SESSION_NOT_FOUND"::equals));
    }
}
