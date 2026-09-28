package com.github.highcumontoa.tokenrotationaccesscontroljava.security;

import com.github.highcumontoa.tokenrotationaccesscontroljava.config.SecurityProperties;
import org.springframework.stereotype.Component;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.Set;

/**
 * 版本化的 HMAC-SHA256 签名密钥管理器（本地内存实现）。
 *
 * <p>语义：
 * <ul>
 *   <li>签发始终使用 {@code currentVersion} 对应的密钥；</li>
 *   <li>{@code rotateKey()} 生成全新随机密钥并把旧版本放入退役集合
 *       （默认立即丢弃退役密钥，旧令牌因验签失败给出 SIGNING_KEY_RETIRED 结论；
 *       若 {@code keepRetiredKeys=true} 则保留退役密钥，旧令牌验签通过后由令牌内嵌的
 *       kid 与当前版本不一致判定为已轮换）；</li>
 *   <li>因此密钥轮换后，所有旧令牌立即失效，无需逐个会话吊销。</li>
 * </ul>
 */
@Component
public class KeyManager {

    private final SecurityProperties properties;
    private final SecureRandom secureRandom = new SecureRandom();

    private volatile int currentVersion;
    private volatile byte[] currentKey;
    private final Set<Integer> retiredVersions = Collections.synchronizedSet(new LinkedHashSet<>());

    public KeyManager(SecurityProperties properties) {
        this.properties = properties;
        this.currentVersion = 1;
        this.currentKey = deriveKey(properties.getKeySeed(), 1);
    }

    /** 由种子与版本派生确定性密钥（仅本地演示）。 */
    private static byte[] deriveKey(String seed, int version) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            digest.update(("v" + version + ":").getBytes(StandardCharsets.UTF_8));
            digest.update(seed.getBytes(StandardCharsets.UTF_8));
            return digest.digest();
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 不可用", e);
        }
    }

    /**
     * 密钥切换：新版本使用随机密钥。默认旧密钥立即退役并从内存清除，
     * 保证旧令牌无法再通过签名校验。
     */
    public synchronized int rotateKey() {
        int oldVersion = currentVersion;
        if (!properties.isKeepRetiredKeys()) {
            retiredVersions.clear();
        }
        retiredVersions.add(oldVersion);
        currentVersion = oldVersion + 1;
        byte[] fresh = new byte[32];
        secureRandom.nextBytes(fresh);
        currentKey = fresh;
        return currentVersion;
    }

    public int getCurrentVersion() {
        return currentVersion;
    }

    /** 返回当前签名密钥的副本与版本。 */
    public synchronized SigningKey currentSigningKey() {
        return new SigningKey(currentVersion, currentKey.clone());
    }

    /**
     * 按 kid 查找可用于验签的密钥。
     *
     * @return 命中的密钥；版本已轮换退役且密钥未保留时返回 null
     */
    public synchronized byte[] verificationKey(int kid) {
        if (kid == currentVersion) {
            return currentKey.clone();
        }
        if (retiredVersions.contains(kid)) {
            if (properties.isKeepRetiredKeys()) {
                // 仅保留从种子派生的初代密钥（演示场景）
                if (kid == 1) {
                    return deriveKey(properties.getKeySeed(), kid);
                }
            }
        }
        return null;
    }

    /** 判定 kid 是否属于已退役版本。 */
    public boolean isRetired(int kid) {
        return kid != currentVersion && retiredVersions.contains(kid);
    }

    /** 计算 HMAC-SHA256。 */
    public static byte[] hmacSha256(byte[] key, byte[] content) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(key, "HmacSHA256"));
            return mac.doFinal(content);
        } catch (Exception e) {
            throw new IllegalStateException("HMAC-SHA256 计算失败", e);
        }
    }

    public static String base64UrlEncode(byte[] data) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(data);
    }

    /** 当前签名密钥视图。 */
    public record SigningKey(int version, byte[] key) {
    }
}
