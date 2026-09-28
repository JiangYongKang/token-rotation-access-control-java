package com.github.highcumontoa.tokenrotationaccesscontroljava.domain;

/**
 * 一次登录产生一个根会话；每次刷新令牌轮换产生一个子会话，共享同一 {@code familyId}，
 * 形成会话链路。复用检测命中时，整条 family 链路（全部后裔会话）一律吊销。
 */
public class SessionInfo {

    private final String id;
    private final String familyId;
    /** 上一代会话 id；登录产生的根会话该值为 null。 */
    private final String parentId;
    private final String userId;
    private final long createdAt;
    private final long refreshExpiryAt;

    private volatile boolean revoked = false;
    private volatile String revokeReason;
    private final Object stateLock = new Object();

    public SessionInfo(String id, String familyId, String parentId, String userId,
                       long createdAt, long refreshExpiryAt) {
        this.id = id;
        this.familyId = familyId;
        this.parentId = parentId;
        this.userId = userId;
        this.createdAt = createdAt;
        this.refreshExpiryAt = refreshExpiryAt;
    }

    public String getId() {
        return id;
    }

    public String getFamilyId() {
        return familyId;
    }

    public String getParentId() {
        return parentId;
    }

    public String getUserId() {
        return userId;
    }

    public long getCreatedAt() {
        return createdAt;
    }

    public long getRefreshExpiryAt() {
        return refreshExpiryAt;
    }

    public boolean isRevoked() {
        return revoked;
    }

    public String getRevokeReason() {
        return revokeReason;
    }

    /**
     * 吊销该会话；重复调用保持幂等并保留最初的吊销原因。
     *
     * @return 若本次调用实际改变了状态返回 true
     */
    public boolean revoke(String reason) {
        synchronized (stateLock) {
            if (revoked) {
                return false;
            }
            revoked = true;
            revokeReason = reason;
            return true;
        }
    }

    public boolean isRefreshExpired(long nowMillis) {
        return nowMillis > refreshExpiryAt;
    }
}
