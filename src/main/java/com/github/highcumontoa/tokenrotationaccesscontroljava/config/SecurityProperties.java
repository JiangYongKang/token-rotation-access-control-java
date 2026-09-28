package com.github.highcumontoa.tokenrotationaccesscontroljava.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * 本地安全模块的可配置项，前缀 {@code app.security}。
 */
@ConfigurationProperties(prefix = "app.security")
public class SecurityProperties {

    /** 访问令牌有效期（秒）。 */
    private long accessTtlSeconds = 900;

    /** 刷新令牌有效期（秒），默认 14 天。 */
    private long refreshTtlSeconds = 14 * 24 * 3600;

    /** 初始签名密钥种子，仅用于本地演示，生产环境应来自密钥管理设施。 */
    private String keySeed = "local-demo-master-key";

    /** 令牌签发者标识（iss 声明）。 */
    private String issuer = "local-token-service";

    /** 吊销会话后是否保留旧版本密钥用于解释性校验；为 false 时密钥轮换立即退役所有旧版本。 */
    private boolean keepRetiredKeys = false;

    public long getAccessTtlSeconds() {
        return accessTtlSeconds;
    }

    public void setAccessTtlSeconds(long accessTtlSeconds) {
        this.accessTtlSeconds = accessTtlSeconds;
    }

    public long getRefreshTtlSeconds() {
        return refreshTtlSeconds;
    }

    public void setRefreshTtlSeconds(long refreshTtlSeconds) {
        this.refreshTtlSeconds = refreshTtlSeconds;
    }

    public String getKeySeed() {
        return keySeed;
    }

    public void setKeySeed(String keySeed) {
        this.keySeed = keySeed;
    }

    public String getIssuer() {
        return issuer;
    }

    public void setIssuer(String issuer) {
        this.issuer = issuer;
    }

    public boolean isKeepRetiredKeys() {
        return keepRetiredKeys;
    }

    public void setKeepRetiredKeys(boolean keepRetiredKeys) {
        this.keepRetiredKeys = keepRetiredKeys;
    }
}
