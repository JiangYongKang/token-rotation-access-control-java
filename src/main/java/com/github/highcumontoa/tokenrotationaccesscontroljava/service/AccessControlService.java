package com.github.highcumontoa.tokenrotationaccesscontroljava.service;

import com.github.highcumontoa.tokenrotationaccesscontroljava.security.AccessDecision;
import com.github.highcumontoa.tokenrotationaccesscontroljava.security.AccessGuard;
import org.springframework.stereotype.Service;

/**
 * 访问控制服务入口：Web 层与拦截器统一通过它做“认证 + 实时权限”判定。
 */
@Service
public class AccessControlService {

    private final AccessGuard accessGuard;

    public AccessControlService(AccessGuard accessGuard) {
        this.accessGuard = accessGuard;
    }

    /** 要求指定权限；失败抛出带区分性原因的异常。 */
    public AccessDecision requirePermission(String bearerToken, String resource, String permission) {
        return accessGuard.requirePermission(stripBearer(bearerToken), resource, permission);
    }

    /** 只做认证。 */
    public AccessDecision authenticate(String bearerToken, String resource) {
        return accessGuard.authenticate(stripBearer(bearerToken), resource);
    }

    private static String stripBearer(String header) {
        if (header == null) {
            return null;
        }
        String trimmed = header.trim();
        if (trimmed.regionMatches(true, 0, "Bearer ", 0, 7)) {
            return trimmed.substring(7).trim();
        }
        return trimmed;
    }
}
