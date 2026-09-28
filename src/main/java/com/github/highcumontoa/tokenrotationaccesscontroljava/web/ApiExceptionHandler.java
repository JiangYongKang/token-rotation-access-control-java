package com.github.highcumontoa.tokenrotationaccesscontroljava.web;

import com.github.highcumontoa.tokenrotationaccesscontroljava.error.ApiException;
import com.github.highcumontoa.tokenrotationaccesscontroljava.error.AuthzReason;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * 统一异常映射：未认证类原因 -> 401；权限不足 -> 403；参数问题 -> 400。
 * 响应体携带 reason code 与可读说明，保证三类拒绝在客户端可区分。
 */
@RestControllerAdvice
public class ApiExceptionHandler {

    @ExceptionHandler(ApiException.class)
    public ResponseEntity<Map<String, Object>> handle(ApiException ex) {
        AuthzReason reason = ex.getReason();
        HttpStatus status = switch (reason) {
            case FORBIDDEN_PERMISSION -> HttpStatus.FORBIDDEN;
            case BAD_REQUEST -> HttpStatus.BAD_REQUEST;
            default -> HttpStatus.UNAUTHORIZED;
        };
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("timestamp", Instant.now().toString());
        body.put("status", status.value());
        body.put("reason", reason.getCode());
        body.put("message", ex.getMessage());
        body.put("credentialId", ex.getCredentialId());
        return ResponseEntity.status(status).body(body);
    }
}
