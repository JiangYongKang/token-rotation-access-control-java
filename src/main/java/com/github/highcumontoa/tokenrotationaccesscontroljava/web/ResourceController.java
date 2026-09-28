package com.github.highcumontoa.tokenrotationaccesscontroljava.web;

import com.github.highcumontoa.tokenrotationaccesscontroljava.security.AccessDecision;
import com.github.highcumontoa.tokenrotationaccesscontroljava.service.AccessControlService;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * 受保护资源：用来验证三类判定结果的可区分性——
 * 未认证(401)、已认证无权限(403)、会话/身份吊销(401 且 reason=session_revoked/user_disabled)。
 */
@RestController
@RequestMapping("/api/resources")
public class ResourceController {

    private final AccessControlService accessControl;

    public ResourceController(AccessControlService accessControl) {
        this.accessControl = accessControl;
    }

    /** 完全公开。 */
    @GetMapping("/public")
    public Map<String, Object> publicResource() {
        return Map.of("resource", "public", "data", "无需登录即可访问");
    }

    /** 任意已认证、会话未吊销用户。 */
    @GetMapping("/profile")
    public Map<String, Object> profile(
            @RequestHeader(value = "Authorization", required = false) String auth) {
        AccessDecision decision = accessControl.requirePermission(
                auth, "/api/resources/profile", null);
        return body(decision, "profile", "当前用户资料");
    }

    /** 需要 article:read 权限。 */
    @GetMapping("/articles")
    public Map<String, Object> articles(
            @RequestHeader(value = "Authorization", required = false) String auth) {
        AccessDecision decision = accessControl.requirePermission(
                auth, "/api/resources/articles", "article:read");
        return body(decision, "articles", "文章列表（要求 article:read）");
    }

    /** 需要 article:write 权限。 */
    @GetMapping("/articles/draft")
    public Map<String, Object> draft(
            @RequestHeader(value = "Authorization", required = false) String auth) {
        AccessDecision decision = accessControl.requirePermission(
                auth, "/api/resources/articles/draft", "article:write");
        return body(decision, "draft", "草稿编辑入口（要求 article:write）");
    }

    private Map<String, Object> body(AccessDecision decision, String name, String data) {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("resource", name);
        body.put("data", data);
        body.put("userId", decision.user().getId());
        body.put("username", decision.user().getUsername());
        body.put("jti", decision.credentialId());
        body.put("sessionId", decision.sessionId());
        body.put("familyId", decision.familyId());
        body.put("effectivePermissions", decision.permissions());
        return body;
    }
}
