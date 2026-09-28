package com.github.highcumontoa.tokenrotationaccesscontroljava.web;

import com.github.highcumontoa.tokenrotationaccesscontroljava.auth.AuthService;
import com.github.highcumontoa.tokenrotationaccesscontroljava.model.IssuedTokens;
import com.github.highcumontoa.tokenrotationaccesscontroljava.model.RefreshConsumeOutcome;
import com.github.highcumontoa.tokenrotationaccesscontroljava.web.dto.ApiError;
import com.github.highcumontoa.tokenrotationaccesscontroljava.web.dto.LoginRequest;
import com.github.highcumontoa.tokenrotationaccesscontroljava.web.dto.LogoutRequest;
import com.github.highcumontoa.tokenrotationaccesscontroljava.web.dto.RefreshRequest;
import com.github.highcumontoa.tokenrotationaccesscontroljava.web.dto.TokenResponse;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

@RestController
@RequestMapping("/api/auth")
public class AuthController {

    private final AuthService authService;

    public AuthController(AuthService authService) {
        this.authService = authService;
    }

    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody LoginRequest request) {
        AuthService.LoginResult result = authService.login(request.username(), request.password());
        if (result instanceof AuthService.LoginResult.Success success) {
            return ResponseEntity.ok(toResponse(success.tokens()));
        }
        AuthService.LoginResult.Failure failure = (AuthService.LoginResult.Failure) result;
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                .body(new ApiError("Unauthorized", failure.reason(), failure.detail(), "-"));
    }

    @PostMapping("/refresh")
    public ResponseEntity<?> refresh(@RequestBody RefreshRequest request) {
        RefreshConsumeOutcome outcome = authService.refresh(request.refreshToken());
        if (outcome instanceof RefreshConsumeOutcome.Rotated rotated) {
            return ResponseEntity.ok(toResponse(rotated.tokens()));
        }
        if (outcome instanceof RefreshConsumeOutcome.Rejected rejected) {
            HttpStatus status = rejected.reason() == com.github.highcumontoa.tokenrotationaccesscontroljava.model.DenyReason.SESSION_REVOKED
                    ? HttpStatus.UNAUTHORIZED
                    : HttpStatus.UNAUTHORIZED;
            return ResponseEntity.status(status)
                    .body(new ApiError("Unauthorized", rejected.reason().name(),
                            rejected.detail(), rejected.credentialId()));
        }
        RefreshConsumeOutcome.ReuseDetected reuse = (RefreshConsumeOutcome.ReuseDetected) outcome;
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                .body(new ApiError("Unauthorized", "REFRESH_TOKEN_REUSE",
                        "refresh token reuse detected; the whole session chain has been revoked: "
                                + reuse.sessionId(),
                        reuse.presentedTokenId()));
    }

    @PostMapping("/logout")
    public ResponseEntity<?> logout(@RequestBody LogoutRequest request) {
        boolean ok = authService.logout(request.refreshToken(), "USER_LOGOUT");
        if (ok) {
            return ResponseEntity.ok(Map.of("outcome", "logged out"));
        }
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                .body(new ApiError("Unauthorized", "SESSION_NOT_FOUND",
                        "refresh token unknown or session already gone", "-"));
    }

    private TokenResponse toResponse(IssuedTokens tokens) {
        return new TokenResponse(tokens.accessToken(), tokens.refreshToken(), tokens.sessionId(),
                tokens.accessTokenId(), tokens.refreshTokenId(), "Bearer",
                tokens.accessTokenTtlSeconds(), tokens.refreshTokenTtlSeconds());
    }
}
