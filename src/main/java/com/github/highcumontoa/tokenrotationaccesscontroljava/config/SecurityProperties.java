package com.github.highcumontoa.tokenrotationaccesscontroljava.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix = "app.security")
public class SecurityProperties {

    private String issuer = "local-iac-service";
    private long accessTokenTtlSeconds = 300;
    private long refreshTokenTtlSeconds = 3600;
    private String masterSecret = "local-development-master-secret-change-me";
    private String initialKeyId = "k1";

    public String getIssuer() {
        return issuer;
    }

    public void setIssuer(String issuer) {
        this.issuer = issuer;
    }

    public long getAccessTokenTtlSeconds() {
        return accessTokenTtlSeconds;
    }

    public void setAccessTokenTtlSeconds(long accessTokenTtlSeconds) {
        this.accessTokenTtlSeconds = accessTokenTtlSeconds;
    }

    public long getRefreshTokenTtlSeconds() {
        return refreshTokenTtlSeconds;
    }

    public void setRefreshTokenTtlSeconds(long refreshTokenTtlSeconds) {
        this.refreshTokenTtlSeconds = refreshTokenTtlSeconds;
    }

    public String getMasterSecret() {
        return masterSecret;
    }

    public void setMasterSecret(String masterSecret) {
        this.masterSecret = masterSecret;
    }

    public String getInitialKeyId() {
        return initialKeyId;
    }

    public void setInitialKeyId(String initialKeyId) {
        this.initialKeyId = initialKeyId;
    }
}
