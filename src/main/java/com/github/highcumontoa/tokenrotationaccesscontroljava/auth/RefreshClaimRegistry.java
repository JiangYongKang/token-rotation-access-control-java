package com.github.highcumontoa.tokenrotationaccesscontroljava.auth;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

/**
 * Distinguishes a genuine refresh-token replay from a request that merely lost a concurrency race.
 *
 * <p>For a given refresh token hash, at most one in-flight request may be the "winner": the first
 * to {@link #tryBegin(String)}. Requests overlapping the winner, or arriving within the short
 * post-rotation grace window afterwards, are reported as {@code CONCURRENT_REFRESH_LOST} and do
 * NOT revoke the session chain: a burst of simultaneous requests is a benign race, not an attack.
 * A presentation of a rotated-out token AFTER the grace window is a true replay and triggers
 * reuse revocation.
 */
@Component
public class RefreshClaimRegistry {

    private record Claim(long startedAtEpochMilli, long graceUntilEpochMilli) {
    }

    /** Hard takeover timeout in case a winner dies while holding the claim. */
    private static final long CLAIM_TTL_MILLIS = 10_000;

    private final long postRotationGraceMillis;
    private final ConcurrentMap<String, Claim> claims = new ConcurrentHashMap<>();

    public RefreshClaimRegistry(
            @Value("${app.security.refresh-grace-millis:1000}") long postRotationGraceMillis) {
        this.postRotationGraceMillis = postRotationGraceMillis;
    }

    /**
     * @return true if this caller is the single owner for the hash; false if another request owns
     *         it or the grace window of a finished rotation is still open.
     */
    public boolean tryBegin(String refreshTokenHash) {
        evictExpired();
        long now = System.currentTimeMillis();
        while (true) {
            Claim fresh = new Claim(now, -1);
            Claim existing = claims.putIfAbsent(refreshTokenHash, fresh);
            if (existing == null) {
                return true;
            }
            if (now < existing.graceUntilEpochMilli()) {
                return false;
            }
            boolean stale = existing.graceUntilEpochMilli() < 0
                    && now - existing.startedAtEpochMilli() > CLAIM_TTL_MILLIS;
            if (stale) {
                if (claims.replace(refreshTokenHash, existing, fresh)) {
                    return true;
                }
                continue;
            }
            return false;
        }
    }

    /** Release immediately (no rotation happened / true replay detected). */
    public void abort(String refreshTokenHash) {
        claims.remove(refreshTokenHash);
    }

    /** Rotation succeeded: keep the claim open for the grace window. */
    public void finishWithRotation(String refreshTokenHash) {
        long now = System.currentTimeMillis();
        claims.computeIfPresent(refreshTokenHash, (k, existing) ->
                new Claim(existing.startedAtEpochMilli(), now + postRotationGraceMillis));
    }

    private void evictExpired() {
        long now = System.currentTimeMillis();
        claims.entrySet().removeIf(e -> {
            Claim c = e.getValue();
            if (c.graceUntilEpochMilli() >= 0) {
                return now > c.graceUntilEpochMilli();
            }
            return now - c.startedAtEpochMilli() > CLAIM_TTL_MILLIS;
        });
    }
}
