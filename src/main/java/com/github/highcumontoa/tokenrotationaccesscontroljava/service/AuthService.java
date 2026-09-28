package com.github.highcumontoa.tokenrotationaccesscontroljava.service;

import com.github.highcumontoa.tokenrotationaccesscontroljava.domain.SessionInfo;
import com.github.highcumontoa.tokenrotationaccesscontroljava.domain.User;
import com.github.highcumontoa.tokenrotationaccesscontroljava.error.ApiException;
import com.github.highcumontoa.tokenrotationaccesscontroljava.error.AuthzReason;
import com.github.highcumontoa.tokenrotationaccesscontroljava.security.AuditLogger;
import com.github.highcumontoa.tokenrotationaccesscontroljava.security.KeyManager;
import com.github.highcumontoa.tokenrotationaccesscontroljava.security.TokenService;
import com.github.highcumontoa.tokenrotationaccesscontroljava.store.SessionStore;
import com.github.highcumontoa.tokenrotationaccesscontroljava.store.UserStore;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.UUID;

/**
 * 身份服务：登录、刷新令牌一次性轮换与复用检测、强制登出、密钥切换。
 *
 * <p>关键不变量（在 family 级锁内保证）：
 * <ul>
 *   <li>刷新令牌 jti 只被成功消费一次；并发刷新同一令牌仅一个成功；</li>
 *   <li>任何对已消费刷新令牌的再次出示都判定为凭证复用，整条会话链路立即吊销；</li>
 *   <li>登出与刷新交叉时锁内串行：已登出链路的刷新一律拒绝；先刷新后登出的旧会话被吊销；</li>
 *   <li>密钥轮换后旧 kid 的令牌验签失败（SIGNING_KEY_RETIRED），无需逐会话处理。</li>
 * </ul>
 */
@Service
public class AuthService {

    private final UserStore userStore;
    private final SessionStore sessionStore;
    private final TokenService tokenService;
    private final KeyManager keyManager;
    private final AuditLogger auditLogger;

    public AuthService(UserStore userStore, SessionStore sessionStore,
                       TokenService tokenService, KeyManager keyManager,
                       AuditLogger auditLogger) {
        this.userStore = userStore;
        this.sessionStore = sessionStore;
        this.tokenService = tokenService;
        this.keyManager = keyManager;
        this.auditLogger = auditLogger;
    }

    /** 登录成功后签发的令牌包。 */
    public record TokenPair(String accessToken, String refreshToken,
                            String accessJti, String refreshJti,
                            String sessionId, String familyId) {
    }

    public TokenPair login(String username, String rawPassword) {
        User user = userStore.findByUsername(username).orElse(null);
        if (user == null || !UserStore.hashPassword(rawPassword).equals(user.getPasswordHash())) {
            auditLogger.log("LOGIN", username, null, null, null, false,
                    AuthzReason.BAD_CREDENTIALS, "用户名或密码错误");
            throw new ApiException(AuthzReason.BAD_CREDENTIALS, null);
        }
        if (!user.isEnabled()) {
            auditLogger.log("LOGIN", user.getId(), null, null, null, false,
                    AuthzReason.USER_DISABLED, "账号已禁用");
            throw new ApiException(AuthzReason.USER_DISABLED, null);
        }

        long now = System.currentTimeMillis();
        String sessionId = UUID.randomUUID().toString();
        String familyId = UUID.randomUUID().toString();
        String accessJti = tokenService.newTokenId();
        String refreshJti = tokenService.newTokenId();

        SessionInfo session = new SessionInfo(sessionId, familyId, null,
                user.getId(), now, now + 14L * 24 * 3600 * 1000);
        sessionStore.save(session);

        String accessToken = tokenService.issueAccessToken(user.getId(), sessionId,
                familyId, accessJti, now);
        String refreshToken = tokenService.issueRefreshToken(user.getId(), sessionId,
                familyId, refreshJti, now);

        auditLogger.log("LOGIN", user.getId(), accessJti, sessionId, familyId, true,
                null, "登录成功，刷新凭证 jti=" + refreshJti);
        return new TokenPair(accessToken, refreshToken, accessJti, refreshJti,
                sessionId, familyId);
    }

    /**
     * 使用刷新令牌轮换出新的访问令牌 + 新的刷新令牌；旧刷新令牌立即作废。
     * 若旧刷新令牌被重复出示（复用攻击或并发重复请求），吊销整条链路并抛出
     * REFRESH_REUSE_DETECTED / SESSION_REVOKED。
     */
    public TokenPair refresh(String rawRefreshToken) {
        TokenService.ParsedToken token;
        try {
            token = tokenService.verify(rawRefreshToken);
        } catch (ApiException e) {
            auditLogger.log("REFRESH", null, e.getCredentialId(), null, null, false,
                    e.getReason(), "刷新前置校验失败");
            throw e;
        }
        if (!TokenService.TYPE_REFRESH.equals(token.type())) {
            auditLogger.log("REFRESH", token.userId(), token.jti(), token.sessionId(),
                    token.familyId(), false, AuthzReason.WRONG_TOKEN_TYPE, null);
            throw new ApiException(AuthzReason.WRONG_TOKEN_TYPE, token.jti());
        }

        synchronized (sessionStore.familyLock(token.familyId())) {
            SessionInfo oldSession = sessionStore.find(token.sessionId());
            if (oldSession == null) {
                auditLogger.log("REFRESH", token.userId(), token.jti(), token.sessionId(),
                        token.familyId(), false, AuthzReason.SESSION_NOT_FOUND, null);
                throw new ApiException(AuthzReason.SESSION_NOT_FOUND, token.jti());
            }

            // 复用检查优先于会话吊销检查：
            // 已消费的一次性刷新凭证再次出现，一定是复用（即使原会话是因正常轮换而退役）；
            // 而未消费凭证出现在已登出链路上，则给出 SESSION_REVOKED，两者原因可区分。
            if (sessionStore.isRefreshConsumed(token.jti())) {
                List<SessionInfo> revoked = sessionStore.revokeFamily(token.familyId(),
                        "refresh_reuse_detected:jti=" + token.jti());
                auditLogger.log("REFRESH_REUSE", token.userId(), token.jti(),
                        token.sessionId(), token.familyId(), false,
                        AuthzReason.REFRESH_REUSE_DETECTED,
                        "刷新令牌复用，已吊销链路会话数=" + revoked.size());
                throw new ApiException(AuthzReason.REFRESH_REUSE_DETECTED, token.jti());
            }

            if (oldSession.isRevoked()) {
                auditLogger.log("REFRESH", token.userId(), token.jti(), token.sessionId(),
                        token.familyId(), false, AuthzReason.SESSION_REVOKED,
                        "链路已吊销: " + oldSession.getRevokeReason());
                throw new ApiException(AuthzReason.SESSION_REVOKED, token.jti());
            }
            if (oldSession.isRefreshExpired(System.currentTimeMillis())) {
                auditLogger.log("REFRESH", token.userId(), token.jti(), token.sessionId(),
                        token.familyId(), false, AuthzReason.REFRESH_EXPIRED, null);
                throw new ApiException(AuthzReason.REFRESH_EXPIRED, token.jti());
            }

            // 原子消费：并发刷新同一令牌时，仅此一处能让一个请求通过
            String previousConsumer = sessionStore.consumeRefresh(token.jti(), oldSession.getId());
            if (previousConsumer != null) {
                List<SessionInfo> revoked = sessionStore.revokeFamily(token.familyId(),
                        "refresh_reuse_detected:jti=" + token.jti());
                auditLogger.log("REFRESH_REUSE", token.userId(), token.jti(),
                        token.sessionId(), token.familyId(), false,
                        AuthzReason.REFRESH_REUSE_DETECTED,
                        "并发刷新同一令牌，落败方触发复用检测，吊销链路会话数=" + revoked.size());
                throw new ApiException(AuthzReason.REFRESH_REUSE_DETECTED, token.jti());
            }

            User user = userStore.findById(token.userId());
            if (user == null || !user.isEnabled()) {
                sessionStore.revokeFamily(token.familyId(), "user_unavailable");
                throw new ApiException(user == null
                        ? AuthzReason.SESSION_NOT_FOUND : AuthzReason.USER_DISABLED, token.jti());
            }

            long now = System.currentTimeMillis();
            String newSessionId = UUID.randomUUID().toString();
            String newAccessJti = tokenService.newTokenId();
            String newRefreshJti = tokenService.newTokenId();
            SessionInfo newSession = new SessionInfo(newSessionId, token.familyId(),
                    oldSession.getId(), user.getId(), now, oldSession.getRefreshExpiryAt());
            sessionStore.save(newSession);
            // 旧会话在轮换后立即退役：旧访问令牌不能再凭旧会话访问
            oldSession.revoke("rotated:newSid=" + newSessionId);

            String accessToken = tokenService.issueAccessToken(user.getId(), newSessionId,
                    token.familyId(), newAccessJti, now);
            String refreshToken = tokenService.issueRefreshToken(user.getId(), newSessionId,
                    token.familyId(), newRefreshJti, now);

            auditLogger.log("REFRESH", user.getId(), token.jti(), token.sessionId(),
                    token.familyId(), true, null,
                    "轮换成功: 旧jti=" + token.jti() + " 已消费，新会话=" + newSessionId
                            + ", 新刷新jti=" + newRefreshJti);
            return new TokenPair(accessToken, refreshToken, newAccessJti, newRefreshJti,
                    newSessionId, token.familyId());
        }
    }

    /**
     * 强制登出：吊销当前会话所在的整条链路，使该令牌及其此前所有轮换后裔立即失效。
     * 与并发刷新在同一把 family 锁上串行。
     */
    public void logout(String rawRefreshToken) {
        TokenService.ParsedToken token = tokenService.verify(rawRefreshToken);
        synchronized (sessionStore.familyLock(token.familyId())) {
            List<SessionInfo> revoked = sessionStore.revokeFamily(token.familyId(),
                    "forced_logout:by=" + token.jti());
            auditLogger.log("LOGOUT", token.userId(), token.jti(), token.sessionId(),
                    token.familyId(), true, null,
                    "强制登出，吊销链路会话数=" + revoked.size());
        }
    }

    /** 管理员强制登出某用户的全部链路。 */
    public int logoutUser(String userId, String operator) {
        int count = 0;
        for (SessionInfo session : sessionStore.allSessions()) {
            if (session.getUserId().equals(userId) && !session.isRevoked()) {
                synchronized (sessionStore.familyLock(session.getFamilyId())) {
                    count += sessionStore.revokeFamily(session.getFamilyId(),
                            "admin_logout:by=" + operator).size();
                }
            }
        }
        auditLogger.log("ADMIN_LOGOUT", userId, null, null, null, true, null,
                "管理员 " + operator + " 吊销该用户会话数=" + count);
        return count;
    }

    /**
     * 密钥切换：新令牌用新版本密钥签发；旧版本密钥立即退役（默认丢弃），
     * 旧令牌再访问时得到 SIGNING_KEY_RETIRED。
     */
    public int rotateSigningKey() {
        int version = keyManager.rotateKey();
        auditLogger.log("KEY_ROTATE", null, null, null, null, true, null,
                "签名密钥已切换到版本 kid=" + version);
        return version;
    }
}
