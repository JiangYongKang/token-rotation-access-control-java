package com.github.highcumontoa.tokenrotationaccesscontroljava.security;

import com.github.highcumontoa.tokenrotationaccesscontroljava.domain.SessionInfo;
import com.github.highcumontoa.tokenrotationaccesscontroljava.domain.User;
import com.github.highcumontoa.tokenrotationaccesscontroljava.error.ApiException;
import com.github.highcumontoa.tokenrotationaccesscontroljava.error.AuthzReason;
import com.github.highcumontoa.tokenrotationaccesscontroljava.store.SessionStore;
import com.github.highcumontoa.tokenrotationaccesscontroljava.store.UserStore;
import org.springframework.stereotype.Component;

import java.util.Set;

/**
 * 访问判定器。每请求执行，且不信任令牌内任何角色/权限快照：
 * <ol>
 *   <li>验签、校验 kid 与过期时间（{@link TokenService}）；</li>
 *   <li>令牌类型必须是 access；</li>
 *   <li>会话必须存在、未被吊销（强制登出 / 复用整链吊销均在此拦截）；</li>
 *   <li>用户必须存在且启用；</li>
 *   <li>按本地存储中的当前角色 / 权限实时判定，修改后旧令牌立即按新状态执行。</li>
 * </ol>
 * 未认证、已认证无权限、被吊销三类原因分别给出不同 {@link AuthzReason}。
 */
@Component
public class AccessGuard {

    private final TokenService tokenService;
    private final SessionStore sessionStore;
    private final UserStore userStore;
    private final AuditLogger auditLogger;

    public AccessGuard(TokenService tokenService, SessionStore sessionStore,
                       UserStore userStore, AuditLogger auditLogger) {
        this.tokenService = tokenService;
        this.sessionStore = sessionStore;
        this.userStore = userStore;
        this.auditLogger = auditLogger;
    }

    /** 认证但暂不做权限判定。 */
    public AccessDecision authenticate(String rawToken, String resource) {
        if (rawToken == null || rawToken.isBlank()) {
            auditLogger.log("ACCESS", null, null, null, null, false,
                    AuthzReason.MISSING_CREDENTIAL, "resource=" + resource);
            return AccessDecision.deny(AuthzReason.MISSING_CREDENTIAL, null, null, null);
        }

        TokenService.ParsedToken token;
        try {
            token = tokenService.verify(rawToken);
        } catch (ApiException e) {
            auditLogger.log("ACCESS", null, null, null, null, false,
                    e.getReason(), "resource=" + resource
                            + (e.getCredentialId() != null ? ", jti=" + e.getCredentialId() : ""));
            return AccessDecision.deny(e.getReason(), e.getCredentialId(), null, null);
        }

        if (!TokenService.TYPE_ACCESS.equals(token.type())) {
            auditLogger.log("ACCESS", token.userId(), token.jti(), token.sessionId(),
                    token.familyId(), false, AuthzReason.WRONG_TOKEN_TYPE, "resource=" + resource);
            return AccessDecision.deny(AuthzReason.WRONG_TOKEN_TYPE, token.jti(),
                    token.sessionId(), token.familyId());
        }

        SessionInfo session = sessionStore.find(token.sessionId());
        if (session == null) {
            auditLogger.log("ACCESS", token.userId(), token.jti(), token.sessionId(),
                    token.familyId(), false, AuthzReason.SESSION_NOT_FOUND, "resource=" + resource);
            return AccessDecision.deny(AuthzReason.SESSION_NOT_FOUND, token.jti(),
                    token.sessionId(), token.familyId());
        }
        if (session.isRevoked()) {
            auditLogger.log("ACCESS", token.userId(), token.jti(), token.sessionId(),
                    token.familyId(), false, AuthzReason.SESSION_REVOKED,
                    "resource=" + resource + ", revokeReason=" + session.getRevokeReason());
            return AccessDecision.deny(AuthzReason.SESSION_REVOKED, token.jti(),
                    token.sessionId(), token.familyId());
        }

        User user = userStore.findById(token.userId());
        if (user == null || !user.isEnabled()) {
            AuthzReason reason = user == null
                    ? AuthzReason.SESSION_NOT_FOUND : AuthzReason.USER_DISABLED;
            auditLogger.log("ACCESS", token.userId(), token.jti(), token.sessionId(),
                    token.familyId(), false, reason, "resource=" + resource);
            return AccessDecision.deny(reason, token.jti(), token.sessionId(), token.familyId());
        }

        Set<String> permissions = userStore.effectivePermissions(user);
        auditLogger.log("ACCESS", user.getId(), token.jti(), token.sessionId(),
                token.familyId(), true, null,
                "resource=" + resource + ", roles=" + user.getRoles()
                        + ", permissions=" + permissions);
        return AccessDecision.permit(user, permissions, token.jti(),
                token.sessionId(), token.familyId());
    }

    /**
     * 认证并做权限判定；失败抛 {@link ApiException}（带区分性的拒绝原因），
     * 成功返回判定结果。
     */
    public AccessDecision requirePermission(String rawToken, String resource, String permission) {
        AccessDecision decision = authenticate(rawToken, resource);
        if (!decision.allowed()) {
            throw new ApiException(decision.reason(), decision.credentialId());
        }
        if (permission != null && !decision.permissions().contains(permission)) {
            auditLogger.log("AUTHZ", decision.user().getId(), decision.credentialId(),
                    decision.sessionId(), decision.familyId(), false,
                    AuthzReason.FORBIDDEN_PERMISSION,
                    "resource=" + resource + ", required=" + permission
                            + ", effective=" + decision.permissions());
            throw new ApiException(AuthzReason.FORBIDDEN_PERMISSION, decision.credentialId());
        }
        return decision;
    }
}
