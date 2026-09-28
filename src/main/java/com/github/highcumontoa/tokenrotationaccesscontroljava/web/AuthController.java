package com.github.highcumontoa.tokenrotationaccesscontroljava.web;

import com.github.highcumontoa.tokenrotationaccesscontroljava.error.ApiException;
import com.github.highcumontoa.tokenrotationaccesscontroljava.error.AuthzReason;
import com.github.highcumontoa.tokenrotationaccesscontroljava.service.AuthService;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * 认证接口：登录、刷新轮换、强制登出。
 */
@RestController
@RequestMapping("/api/auth")
public class AuthController {

    private final AuthService authService;

    public AuthController(AuthService authService) {
        this.authService = authService;
    }

    @PostMapping("/login")
    public Map<String, Object> login(@RequestBody Map<String, String> request) {
        String username = request.get("username");
        String password = request.get("password");
        if (username == null || password == null) {
            throw new ApiException(AuthzReason.BAD_REQUEST);
        }
        AuthService.TokenPair pair = authService.login(username, password);
        return tokenBody(pair);
    }

    @PostMapping("/refresh")
    public Map<String, Object> refresh(@RequestBody Map<String, String> request) {
        String refreshToken = request.get("refreshToken");
        if (refreshToken == null) {
            throw new ApiException(AuthzReason.BAD_REQUEST);
        }
        AuthService.TokenPair pair = authService.refresh(refreshToken);
        return tokenBody(pair);
    }

    @PostMapping("/logout")
    public Map<String, Object> logout(@RequestBody Map<String, String> request) {
        String refreshToken = request.get("refreshToken");
        if (refreshToken == null) {
            throw new ApiException(AuthzReason.BAD_REQUEST);
        }
        authService.logout(refreshToken);
        return Map.of("status", "revoked",
                "message", "会话链路已强制登出，旧访问令牌与刷新令牌立即失效");
    }

    private Map<String, Object> tokenBody(AuthService.TokenPair pair) {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("accessToken", pair.accessToken());
        body.put("refreshToken", pair.refreshToken());
        body.put("tokenType", "Bearer");
        body.put("accessJti", pair.accessJti());
        body.put("refreshJti", pair.refreshJti());
        body.put("sessionId", pair.sessionId());
        body.put("familyId", pair.familyId());
        return body;
    }
}
