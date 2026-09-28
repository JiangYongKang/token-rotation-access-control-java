package com.github.highcumontoa.tokenrotationaccesscontroljava.security;

import com.github.highcumontoa.tokenrotationaccesscontroljava.domain.User;
import com.github.highcumontoa.tokenrotationaccesscontroljava.error.AuthzReason;

/**
 * 访问判定结果：允许时携带当前用户与实时权限集合；拒绝时携带具体原因与凭证标识。
 * 每种拒绝原因一一对应 {@link AuthzReason}，便于调用方与测试区分三类情形。
 */
public record AccessDecision(boolean allowed,
                             User user,
                             java.util.Set<String> permissions,
                             AuthzReason reason,
                             String credentialId,
                             String sessionId,
                             String familyId) {

    public static AccessDecision permit(User user, java.util.Set<String> permissions,
                                        String credentialId, String sessionId, String familyId) {
        return new AccessDecision(true, user, permissions, null, credentialId, sessionId, familyId);
    }

    public static AccessDecision deny(AuthzReason reason, String credentialId,
                                      String sessionId, String familyId) {
        return new AccessDecision(false, null, java.util.Set.of(), reason,
                credentialId, sessionId, familyId);
    }
}
