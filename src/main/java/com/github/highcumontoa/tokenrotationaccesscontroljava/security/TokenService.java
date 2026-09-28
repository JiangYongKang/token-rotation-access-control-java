package com.github.highcumontoa.tokenrotationaccesscontroljava.security;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.highcumontoa.tokenrotationaccesscontroljava.config.SecurityProperties;
import com.github.highcumontoa.tokenrotationaccesscontroljava.error.ApiException;
import com.github.highcumontoa.tokenrotationaccesscontroljava.error.AuthzReason;
import org.springframework.stereotype.Component;

import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * 本地自描述令牌：{@code base64url(JSON 声明).base64url(HMAC-SHA256 签名)}。
 *
 * <p>声明中刻意不携带角色/权限快照——访问判定时始终按 {@code sub} 从本地存储读取
 * 最新角色与权限，从而保证角色/权限修改后旧令牌无法继续凭旧快照访问。
 * 令牌携带 {@code kid}（签名密钥版本）、{@code sid}（会话 id）、{@code fam}（会话链路 id）、
 * {@code jti}（凭证唯一标识）与 {@code typ}（access/refresh）。
 */
@Component
public class TokenService {

    public static final String TYPE_ACCESS = "access";
    public static final String TYPE_REFRESH = "refresh";

    private final KeyManager keyManager;
    private final SecurityProperties properties;
    private final ObjectMapper objectMapper = new ObjectMapper();
    private final SecureRandom secureRandom = new SecureRandom();

    public TokenService(KeyManager keyManager, SecurityProperties properties) {
        this.keyManager = keyManager;
        this.properties = properties;
    }

    /** 生成随机凭证标识（jti），base64url 编码的 16 字节随机数。 */
    public String newTokenId() {
        byte[] bytes = new byte[16];
        secureRandom.nextBytes(bytes);
        return KeyManager.base64UrlEncode(bytes);
    }

    /** 签发访问令牌。 */
    public String issueAccessToken(String userId, String sessionId, String familyId,
                                   String jti, long nowMillis) {
        return signClaims(buildClaims(userId, sessionId, familyId, jti, TYPE_ACCESS,
                nowMillis, nowMillis + properties.getAccessTtlSeconds() * 1000));
    }

    /** 签发刷新令牌（一次性，轮换后旧 jti 即作废）。 */
    public String issueRefreshToken(String userId, String sessionId, String familyId,
                                    String jti, long nowMillis) {
        return signClaims(buildClaims(userId, sessionId, familyId, jti, TYPE_REFRESH,
                nowMillis, nowMillis + properties.getRefreshTtlSeconds() * 1000));
    }

    private Map<String, Object> buildClaims(String userId, String sessionId, String familyId,
                                            String jti, String type, long iat, long exp) {
        KeyManager.SigningKey signingKey = keyManager.currentSigningKey();
        Map<String, Object> claims = new LinkedHashMap<>();
        claims.put("iss", properties.getIssuer());
        claims.put("sub", userId);
        claims.put("sid", sessionId);
        claims.put("fam", familyId);
        claims.put("jti", jti);
        claims.put("typ", type);
        claims.put("kid", signingKey.version());
        claims.put("iat", iat);
        claims.put("exp", exp);
        return claims;
    }

    private String signClaims(Map<String, Object> claims) {
        try {
            int kid = (Integer) claims.get("kid");
            byte[] key = keyManager.verificationKey(kid);
            if (key == null) {
                // 当前版本密钥理论上一定可取；兜底处理
                key = keyManager.currentSigningKey().key();
            }
            String header = KeyManager.base64UrlEncode(
                    objectMapper.writeValueAsBytes(claims));
            byte[] signature = KeyManager.hmacSha256(key,
                    header.getBytes(StandardCharsets.UTF_8));
            return header + "." + KeyManager.base64UrlEncode(signature);
        } catch (Exception e) {
            throw new IllegalStateException("令牌签发失败", e);
        }
    }

    /**
     * 验签并解析令牌。不做会话与用户状态判定（那是 AccessGuard/AuthService 的职责），
     * 只保证：格式合法、签名有效、kid 未退役、未过期。
     */
    public ParsedToken verify(String rawToken) {
        if (rawToken == null || rawToken.isBlank()) {
            throw new ApiException(AuthzReason.MISSING_CREDENTIAL);
        }
        int dot = rawToken.indexOf('.');
        if (dot <= 0 || dot == rawToken.length() - 1 || rawToken.indexOf('.', dot + 1) >= 0) {
            throw new ApiException(AuthzReason.INVALID_CREDENTIAL);
        }
        String headerPart = rawToken.substring(0, dot);
        String signaturePart = rawToken.substring(dot + 1);

        JsonNode claimsNode;
        try {
            claimsNode = objectMapper.readTree(
                    Base64.getUrlDecoder().decode(headerPart));
        } catch (IllegalArgumentException | java.io.IOException e) {
            throw new ApiException(AuthzReason.INVALID_CREDENTIAL);
        }

        int kid = claimsNode.path("kid").asInt(-1);
        byte[] key = keyManager.verificationKey(kid);
        boolean signatureValid = false;
        if (key != null) {
            byte[] expected = KeyManager.hmacSha256(key,
                    headerPart.getBytes(StandardCharsets.UTF_8));
            try {
                byte[] actual = Base64.getUrlDecoder().decode(signaturePart);
                signatureValid = constantTimeEquals(expected, actual);
            } catch (IllegalArgumentException ignored) {
                signatureValid = false;
            }
        }
        if (!signatureValid) {
            // 优先用 kid 解释：版本存在但已退役 → 密钥轮换导致失效；否则是伪造/篡改
            String credentialHint = kid > 0 ? "kid=" + kid : null;
            throw new ApiException(kid > 0 && keyManager.isRetired(kid)
                    ? AuthzReason.SIGNING_KEY_RETIRED
                    : AuthzReason.INVALID_CREDENTIAL, credentialHint);
        }

        try {
            ParsedToken token = new ParsedToken(
                    claimsNode.get("sub").asText(),
                    claimsNode.get("sid").asText(),
                    claimsNode.get("fam").asText(),
                    claimsNode.get("jti").asText(),
                    claimsNode.get("typ").asText(),
                    kid,
                    claimsNode.get("iat").asLong(),
                    claimsNode.get("exp").asLong());
            long now = System.currentTimeMillis();
            if (now > token.exp()) {
                throw new ApiException(TYPE_REFRESH.equals(token.type())
                        ? AuthzReason.REFRESH_EXPIRED
                        : AuthzReason.TOKEN_EXPIRED, token.jti());
            }
            return token;
        } catch (ApiException e) {
            throw e;
        } catch (Exception e) {
            throw new ApiException(AuthzReason.INVALID_CREDENTIAL);
        }
    }

    private static boolean constantTimeEquals(byte[] a, byte[] b) {
        if (a.length != b.length) {
            return false;
        }
        int result = 0;
        for (int i = 0; i < a.length; i++) {
            result |= a[i] ^ b[i];
        }
        return result == 0;
    }

    /** 验签通过后的声明视图。 */
    public record ParsedToken(String userId, String sessionId, String familyId,
                              String jti, String type, int kid,
                              long issuedAt, long exp) {
    }
}
