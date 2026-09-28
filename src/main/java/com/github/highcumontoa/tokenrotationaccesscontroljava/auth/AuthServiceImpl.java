package com.github.highcumontoa.tokenrotationaccesscontroljava.auth;

import com.github.highcumontoa.tokenrotationaccesscontroljava.config.SecurityProperties;
import com.github.highcumontoa.tokenrotationaccesscontroljava.model.DenyReason;
import com.github.highcumontoa.tokenrotationaccesscontroljava.model.IssuedTokens;
import com.github.highcumontoa.tokenrotationaccesscontroljava.model.RefreshConsumeOutcome;
import com.github.highcumontoa.tokenrotationaccesscontroljava.model.Role;
import com.github.highcumontoa.tokenrotationaccesscontroljava.model.SessionInfo;
import com.github.highcumontoa.tokenrotationaccesscontroljava.model.UserAccount;
import com.github.highcumontoa.tokenrotationaccesscontroljava.store.AuditService;
import com.github.highcumontoa.tokenrotationaccesscontroljava.store.SessionStore;
import com.github.highcumontoa.tokenrotationaccesscontroljava.store.UserStore;
import com.github.highcumontoa.tokenrotationaccesscontroljava.token.GeneratedSecret;
import com.github.highcumontoa.tokenrotationaccesscontroljava.token.KeyManager;
import com.github.highcumontoa.tokenrotationaccesscontroljava.token.TokenService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.util.LinkedHashSet;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

@Service
public class AuthServiceImpl implements AuthService {

    private static final Logger log = LoggerFactory.getLogger(AuthServiceImpl.class);

    private final UserStore userStore;
    private final SessionStore sessionStore;
    private final TokenService tokenService;
    private final KeyManager keyManager;
    private final PasswordHasher passwordHasher;
    private final AuditService auditService;
    private final SecurityProperties properties;
    private final RefreshClaimRegistry refreshClaimRegistry;

    public AuthServiceImpl(UserStore userStore, SessionStore sessionStore, TokenService tokenService,
                           KeyManager keyManager, PasswordHasher passwordHasher,
                           AuditService auditService, SecurityProperties properties,
                           RefreshClaimRegistry refreshClaimRegistry) {
        this.userStore = userStore;
        this.sessionStore = sessionStore;
        this.tokenService = tokenService;
        this.keyManager = keyManager;
        this.passwordHasher = passwordHasher;
        this.auditService = auditService;
        this.properties = properties;
        this.refreshClaimRegistry = refreshClaimRegistry;
    }

    @Override
    public LoginResult login(String username, String password) {
        Optional<UserAccount> userOpt = userStore.findByUsername(username);
        if (userOpt.isEmpty() || !passwordHasher.matches(password, userOpt.get().passwordHash())) {
            auditService.record("LOGIN", username, "-", "DENIED",
                    DenyReason.LOGIN_FAILED.name(), "invalid username or password");
            return new LoginResult.Failure(DenyReason.LOGIN_FAILED.name(), "invalid username or password");
        }
        UserAccount user = userOpt.get();
        if (!user.enabled()) {
            auditService.record("LOGIN", username, "-", "DENIED",
                    DenyReason.USER_DISABLED.name(), "account disabled");
            return new LoginResult.Failure(DenyReason.USER_DISABLED.name(), "account disabled");
        }

        String sessionId = "sess-" + UUID.randomUUID();
        GeneratedSecret refresh = tokenService.generateRefreshToken();
        String keyId = keyManager.currentKeyId();
        SessionInfo session = new SessionInfo(sessionId, username, refresh.sha256Hash(), keyId,
                new LinkedHashSet<>(), System.currentTimeMillis(), 0, false, null);
        sessionStore.save(session);
        IssuedTokens tokens = issueTokens(session, user, refresh);
        auditService.record("LOGIN", username, tokens.refreshTokenId(), "GRANTED",
                null, "session=" + sessionId);
        return new LoginResult.Success(tokens);
    }

    @Override
    public RefreshConsumeOutcome refresh(String refreshToken) {
        if (refreshToken == null || refreshToken.isBlank()) {
            return new RefreshConsumeOutcome.Rejected(DenyReason.MALFORMED_TOKEN,
                    "refresh token is empty", "-");
        }
        String presentedHash = tokenService.sha256Hash(refreshToken);
        String credentialId = credentialIdOfHash(presentedHash);

        // All decisioning happens in one per-session critical section. The in-flight claim is only
        // taken once the session is known, so unknown tokens never occupy a claim.
        final Object[] holder = new Object[1];
        final boolean[] claimedHere = {false};
        Optional<SessionInfo> mutated = sessionStore.mutateByRefreshHash(presentedHash, session -> {
            if (session.revoked()) {
                holder[0] = new RefreshConsumeOutcome.Rejected(DenyReason.SESSION_REVOKED,
                        "session revoked: " + session.revokeReason(), credentialId);
                return session;
            }
            // At most one in-flight winner per hash; overlapping requests or requests within the
            // post-rotation grace window are concurrency losers, not attackers.
            if (!refreshClaimRegistry.tryBegin(presentedHash)) {
                holder[0] = new RefreshConsumeOutcome.Rejected(DenyReason.CONCURRENT_REFRESH_LOST,
                        "another request is already rotating this refresh token (or grace window open)",
                        credentialId);
                return session;
            }
            claimedHere[0] = true;
            if (session.usedRefreshTokenHashes().contains(presentedHash)) {
                holder[0] = new RefreshConsumeOutcome.ReuseDetected(
                        session.sessionId(), credentialId, session.username());
                return session.revoked("REFRESH_TOKEN_REUSE: replayed credential " + credentialId);
            }
            if (!presentedHash.equals(session.currentRefreshTokenHash())) {
                holder[0] = new RefreshConsumeOutcome.Rejected(DenyReason.SESSION_NOT_FOUND,
                        "refresh token is not the current credential of the session", credentialId);
                return session;
            }

            GeneratedSecret newRefresh = tokenService.generateRefreshToken();
            String newKeyId = keyManager.currentKeyId();
            SessionInfo rotated = session.rotated(newRefresh.sha256Hash(), newKeyId);
            holder[0] = newRefresh;
            return rotated;
        });

        if (mutated.isEmpty()) {
            auditService.record("REFRESH", "-", credentialId, "DENIED",
                    DenyReason.SESSION_NOT_FOUND.name(),
                    "refresh token does not match any session (never issued, already rotated or revoked)");
            return new RefreshConsumeOutcome.Rejected(DenyReason.SESSION_NOT_FOUND,
                    "refresh token is unknown or has already been used", credentialId);
        }
        SessionInfo finalSession = mutated.get();

        if (holder[0] instanceof RefreshConsumeOutcome.Rejected rejected) {
            if (claimedHere[0]) {
                refreshClaimRegistry.abort(presentedHash);
            }
            if (rejected.reason() == DenyReason.CONCURRENT_REFRESH_LOST) {
                log.info("Concurrent refresh loser credential={} -> CONCURRENT_REFRESH_LOST (no revocation)",
                        credentialId);
            }
            auditService.record("REFRESH", finalSession.username(), credentialId,
                    "DENIED", rejected.reason().name(), rejected.detail());
            return rejected;
        }
        if (holder[0] instanceof RefreshConsumeOutcome.ReuseDetected reuse) {
            // Do not open a grace window on a true replay; immediate retries hit SESSION_REVOKED.
            refreshClaimRegistry.abort(presentedHash);
            log.warn("REFRESH TOKEN REUSE DETECTED session={} presentedCredential={} -> session chain revoked",
                    reuse.sessionId(), reuse.presentedTokenId());
            auditService.record("REFRESH", reuse.username(), credentialId,
                    "DENIED", DenyReason.REFRESH_TOKEN_REUSE.name(),
                    "replayed refresh token; session chain " + reuse.sessionId() + " revoked");
            return reuse;
        }

        GeneratedSecret newRefresh = (GeneratedSecret) holder[0];
        // Rotation succeeded: keep the grace window open so simultaneous stragglers are losers.
        refreshClaimRegistry.finishWithRotation(presentedHash);
        UserAccount user = userStore.findByUsername(finalSession.username()).orElse(null);
        if (user == null) {
            sessionStore.mutate(finalSession.sessionId(), s -> s.revoked("USER_NOT_FOUND"));
            return new RefreshConsumeOutcome.Rejected(DenyReason.USER_NOT_FOUND,
                    "user no longer exists", credentialId);
        }
        IssuedTokens tokens = issueTokens(finalSession, user, newRefresh);
        log.info("Refresh rotated session={} presentedCredential={} newRefreshCredential={} refreshCount={}",
                finalSession.sessionId(), credentialId, tokens.refreshTokenId(),
                finalSession.refreshCount());
        auditService.record("REFRESH", finalSession.username(), tokens.refreshTokenId(),
                "GRANTED", null,
                "session=" + finalSession.sessionId() + " refreshCount="
                        + finalSession.refreshCount() + " replacedCredential=" + credentialId);
        return new RefreshConsumeOutcome.Rotated(tokens, finalSession);
    }

    @Override
    public boolean logout(String refreshToken, String reason) {
        if (refreshToken == null || refreshToken.isBlank()) {
            return false;
        }
        String hash = tokenService.sha256Hash(refreshToken);
        String credentialId = credentialIdOfHash(hash);
        final String[] subject = {null};
        final String[] sessionIdHolder = {null};
        Optional<SessionInfo> result = sessionStore.mutateByRefreshHash(hash, session -> {
            subject[0] = session.username();
            sessionIdHolder[0] = session.sessionId();
            return session.revoked(reason);
        });
        if (result.isEmpty()) {
            auditService.record("LOGOUT", "-", credentialId, "DENIED",
                    DenyReason.SESSION_NOT_FOUND.name(), "token unknown at logout");
            return false;
        }
        auditService.record("LOGOUT", subject[0], credentialId, "GRANTED",
                null, "session=" + sessionIdHolder[0] + " reason=" + reason);
        return true;
    }

    @Override
    public int logoutUser(String username, String reason) {
        int count = 0;
        for (SessionInfo session : sessionStore.findByUsername(username)) {
            if (session.revoked()) {
                continue;
            }
            boolean[] revokedNow = {false};
            sessionStore.mutate(session.sessionId(), s -> {
                if (!s.revoked()) {
                    revokedNow[0] = true;
                    return s.revoked(reason);
                }
                return s;
            });
            if (revokedNow[0]) {
                count++;
            }
        }
        auditService.record("FORCE_LOGOUT", username, "-", "GRANTED",
                null, "sessions revoked=" + count + " reason=" + reason);
        return count;
    }

    @Override
    public int rotateUserCredential(String username, String newRawPassword) {
        Optional<UserAccount> existing = userStore.findByUsername(username);
        if (existing.isEmpty()) {
            return -1;
        }
        // Changing the password bumps the user version: every previously issued access token for
        // the user now fails the CREDENTIALS_CHANGED check. Existing sessions are also revoked.
        userStore.save(existing.get()
                .withPasswordHash(passwordHasher.hash(newRawPassword))
                .withVersionBump());
        int revoked = logoutUser(username, "PASSWORD_ROTATED");
        auditService.record("PASSWORD_ROTATE", username, "-", "GRANTED",
                null, "user version bumped; sessions revoked=" + revoked);
        return revoked;
    }

    @Override
    public int rotateUserRoles(String username, List<String> roles) {
        Optional<UserAccount> existing = userStore.findByUsername(username);
        if (existing.isEmpty()) {
            return -1;
        }
        List<Role> newRoles = roles.stream().map(Role::valueOf).toList();
        userStore.save(existing.get().withRoles(newRoles));
        auditService.record("ROLE_CHANGE", username, "-", "GRANTED",
                null, "new roles=" + newRoles
                        + "; old access tokens invalidated by user version bump");
        return 0;
    }

    private IssuedTokens issueTokens(SessionInfo session, UserAccount user, GeneratedSecret refresh) {
        List<String> roleNames = user.roles().stream().map(Enum::name).toList();
        TokenService.IssuedAccess access = tokenService.issueAccessToken(
                user.username(), roleNames, session.sessionId(), user.version());
        return new IssuedTokens(access.token(), refresh.token(), session.sessionId(),
                access.tokenId(), refresh.tokenId(),
                properties.getAccessTokenTtlSeconds(), properties.getRefreshTokenTtlSeconds());
    }

    private static String credentialIdOfHash(String hash) {
        return "rt-" + hash.substring(0, 12);
    }
}
