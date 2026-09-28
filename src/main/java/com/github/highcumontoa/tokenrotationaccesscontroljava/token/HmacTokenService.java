package com.github.highcumontoa.tokenrotationaccesscontroljava.token;

import com.github.highcumontoa.tokenrotationaccesscontroljava.config.SecurityProperties;
import com.github.highcumontoa.tokenrotationaccesscontroljava.model.DenyReason;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import javax.crypto.Mac;
import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.List;

/**
 * Self-contained access tokens of the form:
 * <pre>base64url(payloadJson).base64url(hmacSha256(payload))</pre>
 * The payload embeds the signing key id, a unique token id (jti), the session id, the user
 * credential version and the role list snapshot. Refresh tokens are opaque high-entropy random
 * strings; only their SHA-256 hash is ever stored server side.
 */
@Component
public class HmacTokenService implements TokenService {

    private static final Logger log = LoggerFactory.getLogger(HmacTokenService.class);
    private static final Base64.Encoder URL_ENCODER = Base64.getUrlEncoder().withoutPadding();
    private static final Base64.Decoder URL_DECODER = Base64.getUrlDecoder();
    private static final SecureRandom RANDOM = new SecureRandom();

    private final SecurityProperties properties;
    private final KeyManager keyManager;

    public HmacTokenService(SecurityProperties properties, KeyManager keyManager) {
        this.properties = properties;
        this.keyManager = keyManager;
    }

    @Override
    public IssuedAccess issueAccessToken(String username, List<String> roles, String sessionId, long userVersion) {
        long now = System.currentTimeMillis();
        long exp = now + properties.getAccessTokenTtlSeconds() * 1000;
        String tokenId = "at-" + randomId();
        String payload = String.join("",
                "{",
                "\"kid\":\"", esc(keyManager.currentKeyId()), "\",",
                "\"jti\":\"", esc(tokenId), "\",",
                "\"sub\":\"", esc(username), "\",",
                "\"sid\":\"", esc(sessionId), "\",",
                "\"ver\":", Long.toString(userVersion), ",",
                "\"roles\":", toJsonArray(roles), ",",
                "\"iat\":", Long.toString(now), ",",
                "\"exp\":", Long.toString(exp),
                "}");
        String token = sign(payload, keyManager.currentKeyId());
        log.debug("Issued access token id={} subject={} session={} keyId={}",
                tokenId, username, sessionId, keyManager.currentKeyId());
        return new IssuedAccess(token, tokenId);
    }

    @Override
    public ParseResult parseAccessToken(String token) {
        String tokenId = null;
        try {
            int dot = token.lastIndexOf('.');
            if (dot <= 0 || dot == token.length() - 1) {
                return new ParseResult.Invalid(DenyReason.MALFORMED_TOKEN,
                        "token must be payload.signature", null);
            }
            String payload = new String(URL_DECODER.decode(token.substring(0, dot)), StandardCharsets.UTF_8);
            String signature = token.substring(dot + 1);

            String kid = readJsonString(payload, "kid");
            tokenId = readJsonString(payload, "jti");
            SecretKey key = keyManager.key(kid);
            if (key == null) {
                log.info("Access token rejected tokenId={} reason=UNKNOWN_SIGNING_KEY kid={}", tokenId, kid);
                return new ParseResult.Invalid(DenyReason.UNKNOWN_SIGNING_KEY,
                        "signing key is no longer known: " + kid, tokenId);
            }
            String expected = sign(payload, kid);
            String expectedSig = expected.substring(expected.lastIndexOf('.') + 1);
            if (!constantTimeEquals(expectedSig, signature)) {
                log.info("Access token rejected tokenId={} reason=INVALID_SIGNATURE", tokenId);
                return new ParseResult.Invalid(DenyReason.INVALID_SIGNATURE,
                        "signature mismatch", tokenId);
            }

            String subject = readJsonString(payload, "sub");
            String sessionId = readJsonString(payload, "sid");
            long ver = readJsonLong(payload, "ver");
            long iat = readJsonLong(payload, "iat");
            long exp = readJsonLong(payload, "exp");
            List<String> roles = readJsonStringArray(payload, "roles");
            if (System.currentTimeMillis() >= exp) {
                log.info("Access token rejected tokenId={} reason=EXPIRED_TOKEN exp={}", tokenId, exp);
                return new ParseResult.Invalid(DenyReason.EXPIRED_TOKEN,
                        "token expired at " + exp, tokenId);
            }
            return new ParseResult.Valid(new Claims(tokenId, subject, sessionId, ver, roles, iat, exp));
        } catch (IllegalArgumentException e) {
            log.info("Access token rejected tokenId={} reason=MALFORMED_TOKEN detail={}",
                    tokenId, e.getMessage());
            return new ParseResult.Invalid(DenyReason.MALFORMED_TOKEN, e.getMessage(), tokenId);
        } catch (Exception e) {
            log.info("Access token rejected tokenId={} reason=MALFORMED_TOKEN detail={}",
                    tokenId, e.toString());
            return new ParseResult.Invalid(DenyReason.MALFORMED_TOKEN, e.toString(), tokenId);
        }
    }

    @Override
    public GeneratedSecret generateRefreshToken() {
        byte[] bytes = new byte[32];
        RANDOM.nextBytes(bytes);
        String raw = "rt." + URL_ENCODER.encodeToString(bytes);
        String tokenId = "rt-" + sha256Hash(raw).substring(0, 12);
        return new GeneratedSecret(raw, tokenId, sha256Hash(raw));
    }

    @Override
    public String sha256Hash(String value) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(value.getBytes(StandardCharsets.UTF_8));
            return DefaultKeyManager.toHex(hash);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 unavailable", e);
        }
    }

    private String sign(String payload, String keyId) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(keyManager.key(keyId));
            byte[] sig = mac.doFinal(payload.getBytes(StandardCharsets.UTF_8));
            return URL_ENCODER.encodeToString(payload.getBytes(StandardCharsets.UTF_8))
                    + "." + URL_ENCODER.encodeToString(sig);
        } catch (Exception e) {
            throw new IllegalStateException("Failed to sign token", e);
        }
    }

    private static boolean constantTimeEquals(String a, String b) {
        return MessageDigest.isEqual(
                a.getBytes(StandardCharsets.UTF_8), b.getBytes(StandardCharsets.UTF_8));
    }

    private static String randomId() {
        byte[] bytes = new byte[12];
        RANDOM.nextBytes(bytes);
        return URL_ENCODER.encodeToString(bytes);
    }

    private static String toJsonArray(List<String> values) {
        StringBuilder sb = new StringBuilder("[");
        for (int i = 0; i < values.size(); i++) {
            if (i > 0) {
                sb.append(',');
            }
            sb.append('"').append(esc(values.get(i))).append('"');
        }
        return sb.append(']').toString();
    }

    private static String esc(String value) {
        return value.replace("\\", "\\\\").replace("\"", "\\\"");
    }

    private static String readJsonString(String json, String key) {
        String marker = "\"" + key + "\":\"";
        int start = json.indexOf(marker);
        if (start < 0) {
            throw new IllegalArgumentException("missing field: " + key);
        }
        start += marker.length();
        StringBuilder sb = new StringBuilder();
        for (int i = start; i < json.length(); i++) {
            char c = json.charAt(i);
            if (c == '\\' && i + 1 < json.length()) {
                sb.append(json.charAt(i + 1));
                i++;
            } else if (c == '"') {
                return sb.toString();
            } else {
                sb.append(c);
            }
        }
        throw new IllegalArgumentException("unterminated field: " + key);
    }

    private static long readJsonLong(String json, String key) {
        String marker = "\"" + key + "\":";
        int start = json.indexOf(marker);
        if (start < 0) {
            throw new IllegalArgumentException("missing field: " + key);
        }
        start += marker.length();
        int end = start;
        while (end < json.length() && (Character.isDigit(json.charAt(end)) || json.charAt(end) == '-')) {
            end++;
        }
        return Long.parseLong(json.substring(start, end));
    }

    private static List<String> readJsonStringArray(String json, String key) {
        String marker = "\"" + key + "\":[";
        int start = json.indexOf(marker);
        if (start < 0) {
            throw new IllegalArgumentException("missing field: " + key);
        }
        start += marker.length();
        int end = json.indexOf(']', start);
        if (end < 0) {
            throw new IllegalArgumentException("unterminated array: " + key);
        }
        String body = json.substring(start, end);
        if (body.isBlank()) {
            return List.of();
        }
        return java.util.Arrays.stream(body.split(","))
                .map(s -> s.replace("\"", "").trim())
                .toList();
    }
}
