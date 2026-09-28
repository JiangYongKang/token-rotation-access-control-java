package com.github.highcumontoa.tokenrotationaccesscontroljava.security;

import com.github.highcumontoa.tokenrotationaccesscontroljava.error.AuthzReason;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;

/**
 * 审计日志：记录登录、访问判定、刷新轮换、复用检测、吊销与密钥切换等事件，
 * 每条记录都带凭证标识（jti / sid / family）与判定依据（允许或具体拒绝原因），
 * 同时输出到应用日志，并保留最近事件供管理接口 / 测试断言。
 */
@Component
public class AuditLogger {

    private static final Logger log = LoggerFactory.getLogger("AUDIT");
    private static final int MAX_EVENTS = 2000;

    private final CopyOnWriteArrayList<AuditEvent> events = new CopyOnWriteArrayList<>();

    public void log(String action, String userId, String credentialId,
                    String sessionId, String familyId, boolean allowed,
                    AuthzReason reason, String detail) {
        AuditEvent event = new AuditEvent(System.currentTimeMillis(), action, userId,
                credentialId, sessionId, familyId, allowed,
                reason == null ? null : reason.getCode(), detail);
        events.add(event);
        trimIfNeeded();

        String basis = allowed ? "ALLOW" : "DENY(" + (reason == null ? "unknown" : reason.getCode()) + ")";
        log.info("{} | action={} | user={} | jti={} | sid={} | fam={} | 判定={} | {}",
                basis, action, userId, credentialId, sessionId, familyId,
                allowed ? "放行" : "拒绝(" + (reason == null ? "" : reason.getDescription()) + ")",
                detail == null ? "" : detail);
    }

    private void trimIfNeeded() {
        synchronized (events) {
            while (events.size() > MAX_EVENTS) {
                events.remove(0);
            }
        }
    }

    public List<AuditEvent> recent(int limit) {
        int size = events.size();
        int from = Math.max(0, size - limit);
        return List.copyOf(events.subList(from, size));
    }

    public List<AuditEvent> byCredential(String credentialId) {
        return events.stream().filter(e -> credentialId.equals(e.credentialId())).toList();
    }

    public void clear() {
        events.clear();
    }

    /** 单条审计事件。 */
    public record AuditEvent(long timestamp, String action, String userId,
                             String credentialId, String sessionId, String familyId,
                             boolean allowed, String reasonCode, String detail) {
    }
}
