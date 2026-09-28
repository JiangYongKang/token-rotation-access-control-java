package com.github.highcumontoa.tokenrotationaccesscontroljava.auth;

import com.github.highcumontoa.tokenrotationaccesscontroljava.model.AuthDecision;
import com.github.highcumontoa.tokenrotationaccesscontroljava.model.DenyReason;
import com.github.highcumontoa.tokenrotationaccesscontroljava.model.Permission;
import com.github.highcumontoa.tokenrotationaccesscontroljava.model.Role;
import com.github.highcumontoa.tokenrotationaccesscontroljava.model.SessionInfo;
import com.github.highcumontoa.tokenrotationaccesscontroljava.model.UserAccount;
import com.github.highcumontoa.tokenrotationaccesscontroljava.store.AuditService;
import com.github.highcumontoa.tokenrotationaccesscontroljava.store.SessionStore;
import com.github.highcumontoa.tokenrotationaccesscontroljava.store.UserStore;
import com.github.highcumontoa.tokenrotationaccesscontroljava.token.Claims;
import com.github.highcumontoa.tokenrotationaccesscontroljava.token.ParseResult;
import com.github.highcumontoa.tokenrotationaccesscontroljava.token.TokenService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Optional;

@Service
public class AccessControlServiceImpl implements AccessControlService {

    private static final Logger log = LoggerFactory.getLogger(AccessControlServiceImpl.class);

    private final TokenService tokenService;
    private final SessionStore sessionStore;
    private final UserStore userStore;
    private final AuditService auditService;

    public AccessControlServiceImpl(TokenService tokenService, SessionStore sessionStore,
                                    UserStore userStore, AuditService auditService) {
        this.tokenService = tokenService;
        this.sessionStore = sessionStore;
        this.userStore = userStore;
        this.auditService = auditService;
    }

    @Override
    public AuthDecision evaluate(String authorizationHeader, Permission required) {
        if (authorizationHeader == null || authorizationHeader.isBlank()) {
            return deny(DenyReason.MISSING_TOKEN, "missing Authorization header", null, null);
        }
        if (!authorizationHeader.startsWith("Bearer ")) {
            return deny(DenyReason.UNSUPPORTED_TOKEN_TYPE,
                    "Authorization header must use Bearer scheme", null, null);
        }
        String token = authorizationHeader.substring("Bearer ".length()).trim();
        if (token.isEmpty()) {
            return deny(DenyReason.MALFORMED_TOKEN, "empty bearer token", null, null);
        }

        ParseResult parseResult = tokenService.parseAccessToken(token);
        if (parseResult instanceof ParseResult.Invalid invalid) {
            return deny(invalid.reason(), invalid.detail(), invalid.tokenId(), null);
        }
        Claims claims = ((ParseResult.Valid) parseResult).claims();

        Optional<SessionInfo> sessionOpt = sessionStore.findById(claims.sessionId());
        if (sessionOpt.isEmpty()) {
            return deny(DenyReason.SESSION_NOT_FOUND,
                    "session " + claims.sessionId() + " no longer exists", claims.tokenId(), claims.subject());
        }
        SessionInfo session = sessionOpt.get();
        if (session.revoked()) {
            return deny(DenyReason.SESSION_REVOKED,
                    "session revoked: " + session.revokeReason(), claims.tokenId(), claims.subject());
        }

        Optional<UserAccount> userOpt = userStore.findByUsername(claims.subject());
        if (userOpt.isEmpty()) {
            return deny(DenyReason.USER_NOT_FOUND, "user no longer exists",
                    claims.tokenId(), claims.subject());
        }
        UserAccount user = userOpt.get();
        if (!user.enabled()) {
            return deny(DenyReason.USER_DISABLED, "user account disabled",
                    claims.tokenId(), claims.subject());
        }
        if (user.version() != claims.userVersion()) {
            return deny(DenyReason.CREDENTIALS_CHANGED,
                    "user credential version " + user.version() + " != token version "
                            + claims.userVersion() + "; old token invalidated",
                    claims.tokenId(), claims.subject());
        }

        // Permissions are always evaluated against the CURRENT roles in the store, so permission
        // revocation takes effect immediately even while the token itself remains cryptographically
        // valid.
        List<Role> currentRoles = user.roles();
        boolean allowed = currentRoles.stream()
                .flatMap(role -> role.permissions().stream())
                .anyMatch(required::equals);
        if (!allowed) {
            return deny(DenyReason.ACCESS_DENIED,
                    "roles " + currentRoles + " do not grant " + required,
                    claims.tokenId(), claims.subject());
        }

        log.info("Access granted tokenId={} subject={} session={} permission={}",
                claims.tokenId(), claims.subject(), claims.sessionId(), required);
        auditService.record("ACCESS", claims.subject(), claims.tokenId(),
                "GRANTED", null, "permission=" + required);
        return new AuthDecision.Granted(claims.subject(), currentRoles,
                claims.sessionId(), claims.tokenId());
    }

    private AuthDecision deny(DenyReason reason, String detail, String tokenId, String subject) {
        log.info("Access denied tokenId={} subject={} reason={} detail={}",
                tokenId, subject, reason, detail);
        auditService.record("ACCESS", subject == null ? "anonymous" : subject,
                tokenId == null ? "-" : tokenId, "DENIED", reason.name(), detail);
        return new AuthDecision.Denied(reason, detail, tokenId);
    }
}
