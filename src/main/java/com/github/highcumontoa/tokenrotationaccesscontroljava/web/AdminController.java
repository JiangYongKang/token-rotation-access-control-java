package com.github.highcumontoa.tokenrotationaccesscontroljava.web;

import com.github.highcumontoa.tokenrotationaccesscontroljava.auth.AuthService;
import com.github.highcumontoa.tokenrotationaccesscontroljava.model.AuditEvent;
import com.github.highcumontoa.tokenrotationaccesscontroljava.model.Permission;
import com.github.highcumontoa.tokenrotationaccesscontroljava.store.AuditService;
import com.github.highcumontoa.tokenrotationaccesscontroljava.token.KeyManager;
import com.github.highcumontoa.tokenrotationaccesscontroljava.web.dto.ChangePasswordRequest;
import com.github.highcumontoa.tokenrotationaccesscontroljava.web.dto.ChangeRolesRequest;
import com.github.highcumontoa.tokenrotationaccesscontroljava.web.dto.ForceLogoutRequest;
import com.github.highcumontoa.tokenrotationaccesscontroljava.web.dto.RotateKeyResponse;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api/admin")
public class AdminController {

    private final AuthService authService;
    private final AuditService auditService;
    private final KeyManager keyManager;

    public AdminController(AuthService authService, AuditService auditService, KeyManager keyManager) {
        this.authService = authService;
        this.auditService = auditService;
        this.keyManager = keyManager;
    }

    @PostMapping("/rotate-key")
    @RequiredPermission(Permission.ADMIN_KEYS)
    public RotateKeyResponse rotateKey() {
        String old = keyManager.currentKeyId();
        String fresh = keyManager.rotate();
        return new RotateKeyResponse(old, fresh);
    }

    @PostMapping("/force-logout")
    @RequiredPermission(Permission.ADMIN_USERS)
    public Map<String, Object> forceLogout(@RequestBody ForceLogoutRequest request) {
        int revoked = authService.logoutUser(request.username(), "ADMIN_FORCE_LOGOUT");
        return Map.of("username", request.username(), "sessionsRevoked", revoked);
    }

    @PostMapping("/change-password")
    @RequiredPermission(Permission.ADMIN_USERS)
    public Map<String, Object> changePassword(@RequestBody ChangePasswordRequest request) {
        int revoked = authService.rotateUserCredential(request.username(), request.newPassword());
        if (revoked < 0) {
            throw new IllegalArgumentException("user not found: " + request.username());
        }
        return Map.of("username", request.username(), "sessionsRevoked", revoked,
                "oldTokensInvalidated", true);
    }

    @PostMapping("/change-roles")
    @RequiredPermission(Permission.ADMIN_USERS)
    public Map<String, Object> changeRoles(@RequestBody ChangeRolesRequest request) {
        int result = authService.rotateUserRoles(request.username(), request.roles());
        if (result < 0) {
            throw new IllegalArgumentException("user not found: " + request.username());
        }
        return Map.of("username", request.username(), "roles", request.roles(),
                "oldTokensInvalidated", true);
    }

    @GetMapping("/audit")
    @RequiredPermission(Permission.ADMIN_AUDIT)
    public List<AuditEvent> audit() {
        return auditService.findAll();
    }
}
