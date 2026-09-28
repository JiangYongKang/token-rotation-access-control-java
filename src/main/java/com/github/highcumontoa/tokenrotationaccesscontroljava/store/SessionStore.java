package com.github.highcumontoa.tokenrotationaccesscontroljava.store;

import com.github.highcumontoa.tokenrotationaccesscontroljava.domain.SessionInfo;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.ConcurrentHashMap;

/**
 * 会话与刷新凭证的本地存储（内存模拟）。
 *
 * <p>并发模型：同一 {@code familyId}（同一条登录链路）的刷新 / 登出操作共用一把锁
 * （{@link #familyLock(String)}），保证：
 * <ul>
 *   <li>同一刷新令牌并发刷新时，只有先拿到锁的请求能消费成功，其余观察到“已消费”，
 *       并触发复用检测、整条链路吊销；</li>
 *   <li>强制登出与刷新交叉时，二者在锁内串行，状态不会错乱；</li>
 *   <li>不同链路互不阻塞。</li>
 * </ul>
 */
@Component
public class SessionStore {

    /** 会话 id -> 会话。 */
    private final ConcurrentHashMap<String, SessionInfo> sessions = new ConcurrentHashMap<>();

    /** family id -> 该链路上的所有会话 id（含已吊销）。 */
    private final ConcurrentHashMap<String, List<String>> familyIndex = new ConcurrentHashMap<>();

    /** 刷新令牌 jti -> 消费该 jti 的会话 id。存在即表示该一次性凭证已使用。 */
    private final ConcurrentHashMap<String, String> consumedRefreshJtis = new ConcurrentHashMap<>();

    /** 链路锁：同链路串行，跨链路并行。 */
    private final ConcurrentHashMap<String, Object> familyLocks = new ConcurrentHashMap<>();

    public void save(SessionInfo session) {
        sessions.put(session.getId(), session);
        familyIndex.computeIfAbsent(session.getFamilyId(), k ->
                Collections.synchronizedList(new ArrayList<>())).add(session.getId());
    }

    public SessionInfo find(String sessionId) {
        return sessions.get(sessionId);
    }

    public Object familyLock(String familyId) {
        return familyLocks.computeIfAbsent(familyId, k -> new Object());
    }

    /**
     * 原子消费一次性刷新令牌。
     *
     * @param jti       刷新令牌凭证标识
     * @param sessionId 消费它的新会话 id
     * @return null 表示消费成功（此前无人使用）；非 null 表示此前已被该会话 id 消费过（复用）
     */
    public String consumeRefresh(String jti, String sessionId) {
        return consumedRefreshJtis.putIfAbsent(jti, sessionId);
    }

    /** 仅查询该刷新令牌是否已被消费，不改变状态。 */
    public boolean isRefreshConsumed(String jti) {
        return consumedRefreshJtis.containsKey(jti);
    }

    /**
     * 吊销整条会话链路（复用检测或强制登出用户时使用）。锁内调用。
     *
     * @return 实际被新吊销的会话列表
     */
    public List<SessionInfo> revokeFamily(String familyId, String reason) {
        List<SessionInfo> changed = new ArrayList<>();
        List<String> ids = familyIndex.get(familyId);
        if (ids != null) {
            synchronized (ids) {
                for (String id : ids) {
                    SessionInfo session = sessions.get(id);
                    if (session != null && session.revoke(reason)) {
                        changed.add(session);
                    }
                }
            }
        }
        return changed;
    }

    /** 吊销单个会话（强制登出当前会话）。 */
    public boolean revoke(String sessionId, String reason) {
        SessionInfo session = sessions.get(sessionId);
        return session != null && session.revoke(reason);
    }

    public boolean isFamilyRevoked(String familyId) {
        List<String> ids = familyIndex.get(familyId);
        if (ids == null) {
            return false;
        }
        synchronized (ids) {
            for (String id : ids) {
                SessionInfo session = sessions.get(id);
                // 链路中存在被吊销会话即视为链路失效（复用检测会整链吊销）
                if (session != null && session.isRevoked()) {
                    return true;
                }
            }
        }
        return false;
    }

    public Collection<SessionInfo> allSessions() {
        return Collections.unmodifiableCollection(sessions.values());
    }
}
