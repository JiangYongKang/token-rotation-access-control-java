package com.github.highcumontoa.tokenrotationaccesscontroljava.web;

import com.github.highcumontoa.tokenrotationaccesscontroljava.model.Permission;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.time.Instant;
import java.util.Map;

@RestController
@RequestMapping("/api/docs")
public class ProtectedController {

    @GetMapping
    @RequiredPermission(Permission.DOCS_READ)
    public Map<String, Object> read(HttpServletRequest request) {
        AuthenticatedUser user = (AuthenticatedUser) request.getAttribute(AuthenticatedUser.REQUEST_ATTRIBUTE);
        return Map.of(
                "resource", "docs",
                "action", "read",
                "principal", user.username(),
                "sessionId", user.sessionId(),
                "accessTokenId", user.tokenId(),
                "at", Instant.now().toString());
    }

    @GetMapping("/write-demo")
    @RequiredPermission(Permission.DOCS_WRITE)
    public Map<String, Object> writeDemo(HttpServletRequest request) {
        AuthenticatedUser user = (AuthenticatedUser) request.getAttribute(AuthenticatedUser.REQUEST_ATTRIBUTE);
        return Map.of(
                "resource", "docs",
                "action", "write",
                "principal", user.username(),
                "sessionId", user.sessionId(),
                "accessTokenId", user.tokenId(),
                "at", Instant.now().toString());
    }
}
