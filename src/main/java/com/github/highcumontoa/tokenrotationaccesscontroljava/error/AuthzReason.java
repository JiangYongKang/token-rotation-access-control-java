package com.github.highcumontoa.tokenrotationaccesscontroljava.error;

/**
 * 身份与访问控制判定的可解释结果。
 *
 * <p>三大类拒绝必须可区分：
 * <ul>
 *   <li>{@link #MISSING_CREDENTIAL} / {@link #INVALID_CREDENTIAL} / {@link #TOKEN_EXPIRED}：未认证；</li>
 *   <li>{@link #FORBIDDEN_PERMISSION}：已认证但权限不足；</li>
 *   <li>{@link #SESSION_REVOKED} / {@link #USER_DISABLED}：身份或会话已被吊销；</li>
 * </ul>
 * 此外还包括令牌轮换 / 复用 / 密钥相关的拒绝原因。
 */
public enum AuthzReason {

    /** 请求未携带任何凭证（未认证）。HTTP 401。 */
    MISSING_CREDENTIAL("missing_credential", "请求缺少 Authorization 头，未认证"),

    /** 令牌格式错误或签名无法通过任何有效密钥校验（未认证）。HTTP 401。 */
    INVALID_CREDENTIAL("invalid_credential", "令牌格式非法或签名无效"),

    /** 访问令牌已过期（未认证）。HTTP 401。 */
    TOKEN_EXPIRED("token_expired", "访问令牌已过期，请使用刷新令牌轮换"),

    /** 令牌由已轮换退役的旧签名密钥签发。HTTP 401。 */
    SIGNING_KEY_RETIRED("signing_key_retired", "签名密钥已轮换，旧令牌立即失效"),

    /** 令牌声明引用的会话不存在（刷新后旧访问令牌的兜底拒绝）。HTTP 401。 */
    SESSION_NOT_FOUND("session_not_found", "令牌引用的会话不存在"),

    /** 会话已被强制登出或因复用被整条链路吊销。HTTP 401。 */
    SESSION_REVOKED("session_revoked", "会话已被吊销（强制登出或刷新令牌复用）"),

    /** 用户账号已被禁用。HTTP 401。 */
    USER_DISABLED("user_disabled", "用户账号已被禁用"),

    /** 刷新令牌类型不匹配。HTTP 401。 */
    WRONG_TOKEN_TYPE("wrong_token_type", "该接口需要刷新令牌，却收到访问令牌"),

    /** 刷新令牌已在之前的轮换中被使用（一次性语义）。HTTP 401。 */
    REFRESH_USED("refresh_token_already_used", "刷新令牌已被使用过，属于一次性凭证"),

    /**
     * 刷新令牌被重复使用，判定为凭证复用：不仅本次拒绝，整条会话链路被吊销。
     * HTTP 401。
     */
    REFRESH_REUSE_DETECTED("refresh_reuse_detected",
            "检测到刷新令牌复用，已吊销该会话链路（含全部后裔令牌）"),

    /** 刷新令牌已过期。HTTP 401。 */
    REFRESH_EXPIRED("refresh_token_expired", "刷新令牌已过期，请重新登录"),

    /** 用户名或密码错误（登录失败）。HTTP 401。 */
    BAD_CREDENTIALS("bad_credentials", "用户名或密码错误"),

    /** 认证通过，但角色/权限不满足要求。HTTP 403。 */
    FORBIDDEN_PERMISSION("forbidden_permission", "已认证但缺少所需权限"),

    /** 请求参数不合法。HTTP 400。 */
    BAD_REQUEST("bad_request", "请求参数不合法");

    private final String code;
    private final String description;

    AuthzReason(String code, String description) {
        this.code = code;
        this.description = description;
    }

    public String getCode() {
        return code;
    }

    public String getDescription() {
        return description;
    }
}
