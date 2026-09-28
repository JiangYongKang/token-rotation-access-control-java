package com.github.highcumontoa.tokenrotationaccesscontroljava.web;

import com.github.highcumontoa.tokenrotationaccesscontroljava.domain.User;
import com.github.highcumontoa.tokenrotationaccesscontroljava.error.ApiException;
import com.github.highcumontoa.tokenrotationaccesscontroljava.error.AuthzReason;
import com.github.highcumontoa.tokenrotationaccesscontroljava.security.AccessDecision;
import com.github.highcumontoa.tokenrotationaccesscontroljava.security.AuditLogger;
import com.github.highcumontoa.tokenrotationaccesscontroljava.service.AccessControlService;
import com.github.highcumontoa.tokenrotationaccesscontroljava.service.AuthService;
import com.github.highcumontoa.tokenrotationaccesscontroljava.store.RoleStore;
import com.github.highcumontoa.tokenrotationaccesscontroljava.store.UserStore;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * 管理接口（本地演示，要求 admin:manage 权限）：修改角色权限、禁用用户、
 * 强制登出用户、密钥切换、查看审计。角色/权限变更后旧令牌访问立即按新状态判定。
 */
@RestController
@RequestMapping("/api/admin")
public class AdminController {

    private final AccessControlService accessControl;
    private final RoleStore roleStore;
    private final UserStore userStore;
    private final AuthService authService;
    private final AuditLogger auditLogger;

    public AdminController(AccessControlService accessControl, RoleStore roleStore,
                           UserStore userStore, AuthService authService,
                           AuditLogger auditLogger) {
        this.accessControl = accessControl;
        this.roleStore = roleStore;
        this.userStore = userStore;
        this.authService = authService;
        this.auditLogger = auditLogger;
    }

    @PostMapping("/roles/{roleName}/permissions")
    public Map<String, Object> changeRolePermission(
            @RequestHeader(value = "Authorization", required = false) String auth,
            @PathVariable String roleName, @RequestBody Map<String, String> body) {
        requireAdmin(auth);
        String permission = body.get("permission");
        String action = body.getOrDefault("action", "add");
        if (permission == null) {
            throw new ApiException(AuthzReason.BAD_REQUEST);
        }
        boolean ok;
        if ("remove".equals(action)) {
            ok = roleStore.removePermission(roleName, permission);
        } else {
            ok = roleStore.addPermission(roleName, permission);
        }
        if (!ok) {
            throw new ApiException(AuthzReason.BAD_REQUEST, null);
        }
        auditLogger.log("ADMIN_PERMISSION", null, null, null, null, true, null,
                action + " role=" + roleName + " permission=" + permission
                        + "，对持有该角色的旧令牌即时生效");
        return Map.of("role", roleName, "permission", permission, "action", action,
                "permissions", roleStore.find(roleName).getPermissions());
    }

    @PostMapping("/users/{username}/enabled")
    public Map<String, Object> setUserEnabled(
            @RequestHeader(value = "Authorization", required = false) String auth,
            @PathVariable String username, @RequestBody Map<String, Boolean> body) {
        requireAdmin(auth);
        User user = userStore.findByUsername(username)
                .orElseThrow(() -> new ApiException(AuthzReason.BAD_REQUEST, null));
        boolean enabled = body.getOrDefault("enabled", true);
        user.setEnabled(enabled);
        auditLogger.log("ADMIN_USER", user.getId(), null, null, null, true, null,
                "用户启用状态设置为 " + enabled);
        return Map.of("username", username, "enabled", enabled);
    }

    @PostMapping("/users/{username}/logout")
    public Map<String, Object> logoutUser(
            @RequestHeader(value = "Authorization", required = false) String auth,
            @PathVariable String username) {
        AccessDecision admin = requireAdmin(auth);
        User user = userStore.findByUsername(username)
                .orElseThrow(() -> new ApiException(AuthzReason.BAD_REQUEST, null));
        int count = authService.logoutUser(user.getId(), admin.user().getUsername());
        return Map.of("username", username, "revokedSessions", count);
    }

    @PostMapping("/keys/rotate")
    public Map<String, Object> rotateKey(
            @RequestHeader(value = "Authorization", required = false) String auth) {
        requireAdmin(auth);
        int version = authService.rotateSigningKey();
        return Map.of("status", "rotated", "newKid", version,
                "effect", "旧 kid 签名的令牌立即失效");
    }

    @GetMapping("/audit")
    public Map<String, Object> audit(
            @RequestHeader(value = "Authorization", required = false) String auth,
            @org.springframework.web.bind.annotation.RequestParam(defaultValue = "100") int limit) {
        requireAdmin(auth);
        List<AuditLogger.AuditEvent> events = auditLogger.recent(Math.min(limit, 500));
        return Map.of("events", events);
    }

    private AccessDecision requireAdmin(String auth) {
        return accessControl.requirePermission(auth, "/api/admin", "admin:manage");
    }
}
