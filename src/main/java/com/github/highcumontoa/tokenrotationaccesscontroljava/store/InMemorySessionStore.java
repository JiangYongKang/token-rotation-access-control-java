package com.github.highcumontoa.tokenrotationaccesscontroljava.store;

import com.github.highcumontoa.tokenrotationaccesscontroljava.model.SessionInfo;
import org.springframework.stereotype.Component;

import java.util.List;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Function;

@Component
public class InMemorySessionStore implements SessionStore {

    private final ConcurrentHashMap<String, SessionInfo> sessions = new ConcurrentHashMap<>();

    @Override
    public SessionInfo save(SessionInfo session) {
        sessions.put(session.sessionId(), session);
        return session;
    }

    @Override
    public Optional<SessionInfo> findById(String sessionId) {
        return Optional.ofNullable(sessions.get(sessionId));
    }

    @Override
    public Optional<SessionInfo> mutate(String sessionId, Function<SessionInfo, SessionInfo> mutation) {
        if (sessionId == null) {
            return Optional.empty();
        }
        synchronized (lockFor(sessionId)) {
            SessionInfo existing = sessions.get(sessionId);
            if (existing == null) {
                return Optional.empty();
            }
            SessionInfo updated = mutation.apply(existing);
            sessions.put(sessionId, updated);
            return Optional.of(updated);
        }
    }

    @Override
    public Optional<SessionInfo> mutateByRefreshHash(String refreshTokenHash,
                                                     Function<SessionInfo, SessionInfo> mutation) {
        if (refreshTokenHash == null) {
            return Optional.empty();
        }
        // Phase 1: lock-free snapshot used only to discover WHICH session to lock. A refresh token
        // hash belongs to at most one session (unique random value, held as the current hash or in
        // the used-hash history).
        String candidateId = sessions.values().stream()
                .filter(s -> refreshTokenHash.equals(s.currentRefreshTokenHash())
                        || s.usedRefreshTokenHashes().contains(refreshTokenHash))
                .map(SessionInfo::sessionId)
                .findFirst()
                .orElse(null);
        if (candidateId == null) {
            return Optional.empty();
        }
        // Phase 2: take the per-session lock and RE-READ the latest state. If a concurrent refresh
        // already rotated, a hash we snapshotted as "current" may now be in the history here; that
        // must be evaluated by the mutation against fresh state rather than the stale snapshot.
        synchronized (lockFor(candidateId)) {
            SessionInfo session = sessions.get(candidateId);
            if (session == null) {
                return Optional.empty();
            }
            if (!refreshTokenHash.equals(session.currentRefreshTokenHash())
                    && !session.usedRefreshTokenHashes().contains(refreshTokenHash)) {
                return Optional.empty();
            }
            SessionInfo updated = mutation.apply(session);
            sessions.put(candidateId, updated);
            return Optional.of(updated);
        }
    }

    @Override
    public List<SessionInfo> findByUsername(String username) {
        return sessions.values().stream()
                .filter(s -> s.username().equals(username))
                .toList();
    }

    @Override
    public List<SessionInfo> findAll() {
        return List.copyOf(sessions.values());
    }

    private Object lockFor(String sessionId) {
        // intern is acceptable for this local in-memory simulation; key space is bounded by
        // active sessions created during a single JVM run.
        return ("session-lock:" + sessionId).intern();
    }
}
