package com.github.highcumontoa.tokenrotationaccesscontroljava.store;

import com.github.highcumontoa.tokenrotationaccesscontroljava.model.SessionInfo;

import java.util.List;
import java.util.Optional;
import java.util.function.Function;

public interface SessionStore {

    SessionInfo save(SessionInfo session);

    Optional<SessionInfo> findById(String sessionId);

    /**
     * Atomically applies the mutation to the session if present. Returns the resulting session
     * (after mutation), or empty if no session with that id exists.
     */
    Optional<SessionInfo> mutate(String sessionId, Function<SessionInfo, SessionInfo> mutation);

    /**
     * Atomically locates the session whose CURRENT refresh token hash or USED-hash history equals
     * the given hash and applies the mutation while holding that session's lock. Lookup and
     * decision therefore cannot interleave across concurrent callers. Returns empty when no
     * session references the hash.
     */
    Optional<SessionInfo> mutateByRefreshHash(String refreshTokenHash,
                                              Function<SessionInfo, SessionInfo> mutation);

    List<SessionInfo> findByUsername(String username);

    List<SessionInfo> findAll();
}
